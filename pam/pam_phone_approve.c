/*
 * pam_phone_approve.c - PAM authentication module backed by a local
 * phone-approval daemon listening on a root-only UNIX socket.
 *
 * Flow:
 *   1. resolve PAM_USER / PAM_SERVICE / PAM_TTY (NULL or "unknown" -> "")
 *   2. show one PAM_TEXT_INFO "Approve on phone..." via PAM_CONV
 *   3. POST /v1/session {"user":...,"service":...,"tty":...}
 *   4. poll GET /v1/session/{id} every 500ms up to 60s
 *      - short-circuit on denied/expired
 *      - fail FAST on session-creation error (daemon down)
 *
 * Deliberately dependency-free: raw POSIX sockets for HTTP/1.1 and
 * strstr() JSON parsing. PAM_AUTHTOK is never touched (no passwords).
 */

#include <security/pam_modules.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SOCKET_PATH      "/run/phone-fprint-auth/daemon.sock"
#define POLL_INTERVAL_NS 500000000L /* 500 ms */
#define POLL_TIMEOUT_S   60
#define IO_TIMEOUT_S     5
#define RESP_BUF_SIZE    8192

/* Module argument `socket=<path>` overrides the default daemon socket. */
static const char *socket_path = SOCKET_PATH;

/* Escape '"' and '\\' so usernames cannot break the JSON body. */
static int json_escape(const char *src, char *dst, size_t dst_cap)
{
    size_t i = 0;

    for (; *src != '\0'; src++) {
        if (*src == '"' || *src == '\\') {
            if (i + 2 >= dst_cap)
                return -1;
            dst[i++] = '\\';
            dst[i++] = *src;
        } else {
            if (i + 1 >= dst_cap)
                return -1;
            dst[i++] = *src;
        }
    }
    dst[i] = '\0';
    return 0;
}

static int unix_connect(void)
{
    int fd;
    struct sockaddr_un addr;
    struct timeval tv = { .tv_sec = IO_TIMEOUT_S, .tv_usec = 0 };
    socklen_t addrlen;

    if (strlen(socket_path) >= sizeof(addr.sun_path))
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                          strlen(socket_path) + 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, addrlen) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n; /* len > 0, so a blocking stream send cannot return 0 */
    }
    return 0;
}

/* Read until the server closes (we send Connection: close). NUL-terminate. */
static int recv_all(int fd, char *buf, size_t cap)
{
    size_t off = 0;

    for (;;) {
        ssize_t n;

        if (off >= cap)
            return -1;
        n = recv(fd, buf + off, cap - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t)n;
    }
    buf[off] = '\0';
    return 0;
}

/* Split headers/body at "\r\n\r\n", parse the status line. */
static int split_response(char *buf, int *status, char **body)
{
    char *sep;
    char *sp;
    char *end;

    sep = strstr(buf, "\r\n\r\n");
    if (sep == NULL)
        return -1;
    *sep = '\0';
    *body = sep + 4;

    sp = strchr(buf, ' ');
    if (sp == NULL)
        return -1;
    *status = (int)strtol(sp + 1, &end, 10);
    if (end == sp + 1)
        return -1;
    return 0;
}

static int http_exchange(const char *method, const char *path, const char *body,
                         char *buf, size_t cap, int *status, char **resp_body)
{
    int fd;
    int reqlen;
    char req[4096];

    if (body != NULL) {
        reqlen = snprintf(req, sizeof(req),
                          "%s %s HTTP/1.1\r\n"
                          "Host: localhost\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          method, path, strlen(body), body);
    } else {
        reqlen = snprintf(req, sizeof(req),
                          "%s %s HTTP/1.1\r\n"
                          "Host: localhost\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          method, path);
    }
    if (reqlen < 0 || (size_t)reqlen >= sizeof(req))
        return -1;

    fd = unix_connect();
    if (fd < 0)
        return -1;
    if (send_all(fd, req, (size_t)reqlen) != 0) {
        close(fd);
        return -1;
    }
    if (recv_all(fd, buf, cap) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return split_response(buf, status, resp_body);
}

static const char *canonicalize(const char *value)
{
    if (value == NULL || *value == '\0' || strcmp(value, "unknown") == 0)
        return "";
    return value;
}

static void show_info(pam_handle_t *pamh)
{
    static const struct pam_message msgs[] = {
        { .msg_style = PAM_TEXT_INFO, .msg = "Approve on phone..." },
    };
    const struct pam_message *msg_ptr = msgs;
    struct pam_response *resp = NULL;
    struct pam_conv *conv = NULL;

    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS)
        return;
    if (conv == NULL || conv->conv == NULL)
        return;
    if (conv->conv(1, &msg_ptr, &resp, conv->appdata_ptr) != PAM_SUCCESS)
        return;
    if (resp != NULL) {
        if (resp[0].resp != NULL)
            free(resp[0].resp);
        free(resp);
    }
}

/* POST /v1/session, extract the "id" field. Fail fast on any error. */
static int create_session(const char *user, const char *service, const char *tty,
                          char *id, size_t id_cap)
{
    char esc_user[256], esc_service[256], esc_tty[256];
    char body[1024];
    char buf[RESP_BUF_SIZE];
    char *resp_body = NULL, *idp;
    size_t i;
    int status = 0, n;

    if (json_escape(user, esc_user, sizeof(esc_user)) != 0 ||
        json_escape(service, esc_service, sizeof(esc_service)) != 0 ||
        json_escape(tty, esc_tty, sizeof(esc_tty)) != 0)
        return PAM_AUTH_ERR;

    n = snprintf(body, sizeof(body),
                 "{\"user\":\"%s\",\"service\":\"%s\",\"tty\":\"%s\"}",
                 esc_user, esc_service, esc_tty);
    if (n < 0 || (size_t)n >= sizeof(body))
        return PAM_AUTH_ERR;

    if (http_exchange("POST", "/v1/session", body, buf, sizeof(buf),
                      &status, &resp_body) != 0)
        return PAM_AUTH_ERR; /* daemon down: fail fast, no 60s hang */
    if (status < 200 || status >= 300)
        return PAM_AUTH_ERR;

    idp = strstr(resp_body, "\"id\":\"");
    if (idp == NULL)
        return PAM_AUTH_ERR;
    idp += strlen("\"id\":\"");

    for (i = 0; idp[i] != '\0' && idp[i] != '"' && i + 1 < id_cap; i++)
        id[i] = idp[i];
    if (i == 0)
        return PAM_AUTH_ERR;
    id[i] = '\0';
    return PAM_SUCCESS;
}

/* GET /v1/session/{id} every 500ms; short-circuit on denied/expired. */
static int poll_session(const char *id)
{
    char path[160];
    const struct timespec interval = { .tv_sec = 0, .tv_nsec = POLL_INTERVAL_NS };
    time_t deadline;
    int n;

    n = snprintf(path, sizeof(path), "/v1/session/%s", id);
    if (n < 0 || (size_t)n >= sizeof(path))
        return PAM_AUTH_ERR;

    deadline = time(NULL) + POLL_TIMEOUT_S;

    for (;;) {
        char buf[RESP_BUF_SIZE];
        char *resp_body = NULL;
        int status = 0;

        if (http_exchange("GET", path, NULL, buf, sizeof(buf),
                          &status, &resp_body) == 0 &&
            status >= 200 && status < 300) {
            if (strstr(resp_body, "\"status\":\"approved\"") != NULL)
                return PAM_SUCCESS;
            if (strstr(resp_body, "\"status\":\"denied\"") != NULL ||
                strstr(resp_body, "\"status\":\"expired\"") != NULL)
                return PAM_AUTH_ERR;
        }
        if (time(NULL) >= deadline)
            return PAM_AUTH_ERR;
        nanosleep(&interval, NULL);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *user = NULL, *service = NULL, *tty = NULL;
    char id[128];
    int i;
    int rc;

    (void)flags;

    for (i = 0; i < argc; i++) {
        if (argv[i] != NULL && strncmp(argv[i], "socket=", 7) == 0 &&
            argv[i][7] != '\0')
            socket_path = argv[i] + 7;
    }

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL ||
        *user == '\0')
        return PAM_AUTH_ERR;

    (void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    (void)pam_get_item(pamh, PAM_TTY, (const void **)&tty);
    service = canonicalize(service);
    tty = canonicalize(tty);

    show_info(pamh);

    rc = create_session(user, service, tty, id, sizeof(id));
    if (rc != PAM_SUCCESS)
        return rc;

    return poll_session(id);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
