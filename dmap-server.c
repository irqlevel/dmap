#include "dmap-server.h"
#include "dmap-trace-helpers.h"
#include "dmap-malloc.h"
#include "dmap.h"
#include "dmap-handler.h"

#include <linux/kthread.h>
#include <linux/delay.h>

int dmap_server_init(struct dmap_server *srv)
{
	memset(srv, 0, sizeof(*srv));
	mutex_init(&srv->mutex);
	atomic64_set(&srv->next_con_id, 0);
	INIT_LIST_HEAD(&srv->con_list);
	return 0;
}

static int dmap_server_con_thread(void *data)
{
	struct dmap_server_con *con;
	struct dmap_server *srv;
	struct dmap *map;
	u32 type, len, result;
	int r;

	con = (struct dmap_server_con *)data;
	srv = con->srv;
	map = container_of(srv, struct dmap, server);

	TRACE("con 0x%p id %llu running, thread 0x%p", con, con->id, current);

	while (!kthread_should_stop() && !con->stopping) {
		r = dmap_con_recv(&con->con, &con->request,
				  &type, &len, &result);
		if (r) {
			if (r == -EAGAIN) {
				r = 0;
				continue;
			}

			TRACE_ERR(r, "con 0x%p id %llu recv failed",
				  con, con->id);
			break;
		}

		if (kthread_should_stop() || con->stopping)
			break;

		result = dmap_handle_request(map, type, con->request.body, len,
					     con->response.body, &len);

		r = dmap_con_send(&con->con, type, len, result,
				  &con->response);
		if (r) {
			TRACE_ERR(r, "con 0x%p id %llu send failed",
				  con, con->id);
			break;
		}
	}

	TRACE("con 0x%p id %llu stopped, thread 0x%p", con, con->id, current);

	return 0;
}

static int dmap_server_con_start(struct dmap_server *srv, struct socket *sock)
{
	struct dmap_server_con *con;
	struct task_struct *thread;
	int r;

	con = dmap_kzalloc(sizeof(*con), GFP_KERNEL);
	if (!con)
		return -ENOMEM;

	r = dmap_con_init(&con->con);
	if (r)
		goto free_con;

	con->id = atomic64_inc_return(&srv->next_con_id);
	mutex_init(&con->mutex);
	INIT_LIST_HEAD(&con->list);

	thread = kthread_create(dmap_server_con_thread, con, "dmap-con-%llu",
				con->id);
	if (IS_ERR(thread)) {
		r = PTR_ERR(thread);
		goto deinit_con;
	}

	r = dmap_con_set_socket(&con->con, sock);
	if (r)
		goto del_thread;

	get_task_struct(thread);
	con->thread = thread;
	con->srv = srv;

	mutex_lock(&srv->mutex);
	list_add_tail(&con->list, &srv->con_list);
	mutex_unlock(&srv->mutex);

	wake_up_process(thread);

	return 0;

del_thread:
	kthread_stop(thread);
deinit_con:
	dmap_con_deinit(&con->con);
free_con:
	dmap_kfree(con);
	return r;
}

static void dmap_server_con_release(struct dmap_server_con *con)
{
	mutex_lock(&con->mutex);
	if (con->thread) {
		con->stopping = true;
		PRINTK("going to stop connection thread 0x%p", con->thread);
		kthread_stop(con->thread);
		put_task_struct(con->thread);
		con->thread = NULL;
		dmap_con_deinit(&con->con);
		con->stopping = false;
	}
	mutex_unlock(&con->mutex);
	dmap_kfree(con);
}

static int dmap_server_thread(void *data)
{
	struct dmap_server *srv;
	struct socket *sock;
	int r;

	srv = (struct dmap_server *)data;
	PRINTK("server 0x%p running, thread 0x%p", srv, current);

	while (!kthread_should_stop() && !srv->stopping) {

		TRACE("accepting");

		r = ksock_accept(&sock, srv->sock);
		if (r) {
			TRACE_ERR(r, "accept failed");
			continue;
		}

		TRACE("accepted");

		r = dmap_server_con_start(srv, sock);
		if (r) {
			TRACE_ERR(r, "connection start failed");
			ksock_release(sock);
		}
	}

	PRINTK("server 0x%p stopped, thread 0x%p", srv, current);

	return 0;
}

int dmap_server_start(struct dmap_server *srv, char *host, int port)
{
	struct task_struct *thread;
	struct socket *sock;
	int r;
	int i;

	mutex_lock(&srv->mutex);
	if (srv->thread) {
		r = -EEXIST;
		goto unlock;
	}

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
	INIT_LIST_HEAD(&srv->con_list);

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
	struct dmap_server_con *con, *tmp;
	int r;

	mutex_lock(&srv->mutex);
	if (srv->thread) {
		srv->stopping = true;
		ksock_abort_accept(srv->sock);
		PRINTK("going to stop server thread 0x%p", srv->thread);
		kthread_stop(srv->thread);
		put_task_struct(srv->thread);
		srv->thread = NULL;
		ksock_release(srv->sock);
		srv->sock = NULL;

		list_for_each_entry_safe(con, tmp, &srv->con_list, list) {
			list_del_init(&con->list);
			dmap_server_con_release(con);
		}

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
