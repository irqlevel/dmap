#include "dmap-connection.h"
#include "ksocket.h"
#include "dmap-trace-helpers.h"

int dmap_con_init(struct dmap_connection *con)
{
	TRACE("con 0x%p init", con);

	memset(con, 0, sizeof(*con));
	init_rwsem(&con->rw_sem);

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

	down_write(&con->rw_sem);
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
	up_write(&con->rw_sem);
	return r;
}

int dmap_con_close(struct dmap_connection *con)
{
	down_write(&con->rw_sem);
	if (con->sock) {
		ksock_release(con->sock);
		con->sock = NULL;
		con->host[0] = '\0';
		con->port = 0;
	}
	up_write(&con->rw_sem);
	return 0;
}

static int __dmap_send_req(struct dmap_connection *con, u32 type, u32 len,
			    void *req)
{
	struct dmap_req_header *header;
	u32 wrote;
	int r;

	header = req;
	if (len < sizeof(*header))
		return -EINVAL;

	if (len > DMAP_REQ_BODY_MAX)
		return -EINVAL;

	header->magic = cpu_to_le32(DMAP_REQ_MAGIC);
	header->len = cpu_to_le32(len);
	header->type = cpu_to_le32(type);

	r = ksock_send(con->sock, req, len);
	if (r < 0)
		return r;
	wrote = r;

	if (wrote != len)
		return -EIO;

	return 0;
}

static int dmap_send_req(struct dmap_connection *con,
			  struct dmap_req_header *req)
{
	u32 wrote;
	int r;

	r = ksock_send(con->sock, req, le32_to_cpu(req->len));
	if (r < 0)
		return r;
	wrote = r;

	if (wrote != le32_to_cpu(req->len))
		return -EIO;

	return 0;
}

static int __dmap_recv_resp(struct dmap_connection *con, u32 type, u32 len,
			     void *body)
{
	struct dmap_resp_header header;
	u32 read;
	u32 llen, ltype, lresult;
	int r;

	r = ksock_recv(con->sock, (unsigned char *)&header,
			     sizeof(header));
	if (r < 0)
		return r;
	read = r;

	if (read != sizeof(header))
		return -EIO;

	if (le32_to_cpu(header.magic) != DMAP_RESP_MAGIC)
		return -EINVAL;

	ltype = le32_to_cpu(header.type);
	llen = le32_to_cpu(header.len);
	lresult = le32_to_cpu(header.result);

	if (llen > DMAP_RESP_BODY_MAX)
		return -EINVAL;
	if (llen < sizeof(header))
		return -EINVAL;
	llen -= sizeof(header);
	if (type != ltype)
		return -EINVAL;
	if (llen != 0) {
		if (llen != len)
			return -EINVAL;

		r = ksock_recv(con->sock, body, llen);
		if (r < 0)
			return r;
		read = r;
		if (read != llen) {
			r = -EIO;
			TRACE_ERR(r, "incomplete read %d llen %d", read, len);
			return r;
		}
	} else {
		/* in this case lresult should be != 0 */
		if (lresult == 0)
			lresult = -EINVAL;
	}

	return lresult;
}

static int dmap_recv_resp(struct dmap_connection *con, u32 type, u32 len,
			   void **body)
{
	void *lbody;
	int r;

	lbody = dmap_kmalloc(len, GFP_KERNEL);
	if (!lbody)
		return -ENOMEM;

	r = __dmap_recv_resp(con, type, len, lbody);
	if (r) {
		dmap_kfree(lbody);
		return r;
	}
	*body = lbody;
	return 0;
}
