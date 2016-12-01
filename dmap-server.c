#include "dmap-server.h"
#include "dmap-trace-helpers.h"

#include <linux/kthread.h>
#include <linux/delay.h>

int dmap_server_init(struct dmap_server *srv)
{
	memset(srv, 0, sizeof(*srv));
	mutex_init(&srv->mutex);
	return 0;
}

static int dmap_server_thread(void *data)
{
	struct dmap_server *srv;
	struct socket *sock;
	int r;

	srv = (struct dmap_server *)data;
	while (!kthread_should_stop() && !srv->stopping) {

		TRACE("accepting");

		r = ksock_accept(&sock, srv->sock);
		if (r) {
			TRACE_ERR(r, "accept failed");
			continue;
		}

		TRACE("accepted");

		ksock_release(sock);
	}

	return 0;
}

int dmap_server_start(struct dmap_server *srv, char *host, int port)
{
	struct task_struct *thread;
	struct socket *sock;
	int r;
	int i;

	mutex_lock(&srv->mutex);
	snprintf(srv->host, ARRAY_SIZE(srv->host), "%s", host);
	srv->port = port;

	for (i = 0; i < 5; i++) {
		r = ksock_listen_host(&sock, host, port, 5);
		if (r) {
			TRACE_ERR(r, "listen failed");
			if (r == -EADDRINUSE) {
				msleep_interruptible(100);
				continue;
			}
			goto unlock;
		} else
			break;
	}

	if (r)
		goto unlock;

	thread = kthread_create(dmap_server_thread, srv, "dmap-server");
	if (IS_ERR(thread)) {
		r = PTR_ERR(thread);
		goto release_sock;
	}

	get_task_struct(thread);
	srv->thread = thread;
	srv->sock = sock;
	wake_up_process(thread);
	r = 0;
	goto unlock;

release_sock:
	ksock_release(sock);
unlock:
	mutex_unlock(&srv->mutex);
	return r;
}

int dmap_server_stop(struct dmap_server *srv)
{
	int r;

	mutex_lock(&srv->mutex);
	if (srv->thread) {
		srv->stopping = true;
		ksock_abort_accept(srv->sock);
		kthread_stop(srv->thread);
		put_task_struct(srv->thread);
		srv->thread = NULL;
		ksock_release(srv->sock);
		srv->sock = NULL;
		srv->stopping = false;
		r = 0;
	} else
		r = -ENOTTY;
	mutex_unlock(&srv->mutex);
	return r;
}

void dmap_server_deinit(struct dmap_server *srv)
{
	dmap_server_stop(srv);
}
