#include "dmap-connection.h"
#include "ksocket.h"
#include "dmap-trace-helpers.h"
#include "dmap-malloc.h"

#include <linux/gfp.h>

int dmap_con_init(struct dmap_connection *con)
{
	memset(con, 0, sizeof(*con));
	mutex_init(&con->mutex);

	return 0;
}

void dmap_con_deinit(struct dmap_connection *con)
{
	dmap_con_close(con);
}

int dmap_con_connect(struct dmap_connection *con, char *host, u16 port)
{
	int r;
	struct socket *sock;

	mutex_lock(&con->mutex);
	if (con->sock) {
		r = -EEXIST;
		goto unlock;
	}

	r = ksock_connect_host(&sock, host, port);
	if (r) {
		TRACE_ERR(r, "connect failed");
		goto unlock;
	}

	r = ksock_set_nodelay(sock, true);
	if (r) {
		TRACE_ERR(r, "set no delay failed");
		goto release_sock;
	}

	snprintf(con->host, ARRAY_SIZE(con->host), "%s", host);
	con->port = port;
	con->sock = sock;

	r = 0;
	goto unlock;

release_sock:
	ksock_release(sock);
unlock:
	mutex_unlock(&con->mutex);
	return r;
}

int dmap_con_set_socket(struct dmap_connection *con, struct socket *sock)
{
	int r;

	mutex_lock(&con->mutex);
	if (con->sock) {
		r = -EEXIST;
		goto unlock;
	}

	con->sock = sock;
	r = 0;
unlock:
	mutex_unlock(&con->mutex);
	return r;
}

int dmap_con_close(struct dmap_connection *con)
{
	mutex_lock(&con->mutex);
	if (con->sock) {
		ksock_release(con->sock);
		con->sock = NULL;
		con->host[0] = '\0';
		con->port = 0;
	}
	mutex_unlock(&con->mutex);
	return 0;
}

int dmap_con_send(struct dmap_connection *con, u32 type, u32 len,
		  u32 result, struct dmap_packet *packet)
{
	int r;

	mutex_lock(&con->mutex);
	if (!con->sock) {
		r = -EBADF;
		goto unlock;
	}

	if (len > sizeof(packet->body)) {
		r = -EINVAL;
		goto unlock;
	}

	packet->header.magic = cpu_to_le32(DMAP_PACKET_MAGIC);
	packet->header.len = cpu_to_le32(len);
	packet->header.type = cpu_to_le32(type);
	packet->header.result = cpu_to_le32(result);

	r = ksock_send(con->sock, packet, sizeof(packet->header) + len);
	if (r < 0)
		goto unlock;

	if (r != (sizeof(packet->header) + len)) {
		r = -EIO;
		goto unlock;
	}

	r = 0;

unlock:
	mutex_unlock(&con->mutex);
	return r;
}

int dmap_con_recv(struct dmap_connection *con, struct dmap_packet *packet,
		  u32 *type, u32 *len, u32 *result)
{
	int r;
	u32 magic, ltype, llen, lresult;

	mutex_lock(&con->mutex);
	if (!con->sock) {
		r = -EBADF;
		goto unlock;
	}

	r = ksock_recv(con->sock, &packet->header, sizeof(packet->header));
	if (r < 0)
		goto unlock;

	if (r != sizeof(packet->header)) {
		r = -EIO;
		goto unlock;
	}

	magic = le32_to_cpu(packet->header.magic);
	ltype = le32_to_cpu(packet->header.type);
	llen = le32_to_cpu(packet->header.len);
	lresult = le32_to_cpu(packet->header.result);

	if (magic != DMAP_PACKET_MAGIC) {
		r = -EBADF;
		goto unlock;
	}

	if (llen > sizeof(packet->body)) {
		r = -EBADF;
		goto unlock;
	}

	r = ksock_recv(con->sock, packet->body, llen);
	if (r < 0)
		goto unlock;

	if (r != llen) {
		r = -EIO;
		goto unlock;
	}

	*type = ltype;
	*len = llen;
	*result = lresult;
	r = 0;

unlock:
	mutex_unlock(&con->mutex);
	return r;
}

int dmap_con_recv_check(struct dmap_connection *con, struct dmap_packet *packet,
			u32 type, u32 len)
{
	u32 ltype, llen, lresult;
	int r;

	r = dmap_con_recv(con, packet, &ltype, &llen, &lresult);
	if (r)
		return r;

	if (llen != len)
		return -EBADF;

	if (ltype != type)
		return -EBADF;

	return lresult;
}
