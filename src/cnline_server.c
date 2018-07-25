#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/sha.h>
#include <limits.h>
#include <libgen.h>

#include "cnline_protocol.h"

static void signup(int conn_fd);
static void login(int conn_fd);
static void msg(int conn_fd);
static void file(int conn_fd, fd_set* fds);
static void history(int conn_fd);
static void logout(int conn_fd);
static void refresh(int conn_fd);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: ./cnline_server [.info]\n");
    return 0;
  }
  FILE* fp = fopen(argv[1], "r");
  if (fp == NULL) {
    fprintf(stderr, "'%s' cannot open\n", argv[1]);
    return 0;
  }
  char server_dir[PATH_MAX];
  if (!fscanf(fp, "server_dir=%s", server_dir)) {
    fprintf(stderr, ".info usage: server_dir=[path]\n");
    return 0;
  }
  fclose(fp);
  struct stat stat;
  if (lstat(server_dir, &stat) < 0) {
    mkdir(server_dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  }
  if (chdir(server_dir) < 0) {
    fprintf(stderr, "cannot change to %s directory\n", server_dir);
    return 0;
  }
  
	struct sockaddr_in serv;
	int listen_fd;
  int conn_fd, conn_len;
	
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(CNLINE_SERVER_PORT);
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  
  int optval = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	
  if (bind(listen_fd, (struct sockaddr *)&serv, sizeof(struct sockaddr)) < 0) {
    fprintf(stderr, "bind() error code: %s\n", strerror(errno));
    return 0;
  }
	if (listen(listen_fd, SOMAXCONN) < 0) {
    fprintf(stderr, "bind() error code: %s\n", strerror(errno));
    return 0;
  }
  
  fd_set fds;
  fd_set readfds;
  FD_ZERO(&fds);
  FD_SET(listen_fd, &fds);
  int i;
  
  while (1) {
    readfds = fds;
    if (select(FD_SETSIZE, &readfds, NULL, NULL, NULL) < 0) {
      if (errno == EINTR) {
        continue;
      }
      fprintf(stderr, "select() fail\n");
      break;
    }
    for (i = 0; i < FD_SETSIZE; i++) {
      if (FD_ISSET(i, &readfds)) {
        if (i == listen_fd) {
          memset(&serv, 0, sizeof(serv));
          conn_len = 0;
          conn_fd = accept(listen_fd, (struct sockaddr*) &serv, (socklen_t*) &conn_len);
          if (conn_fd < 0) {
            if (errno == EAGAIN || errno == ENFILE || errno == EINTR) {
              continue;
            }
            else {
              fprintf(stderr, "accept() error: %s\n", strerror(errno));
              continue;
            }
          }
          FD_SET(conn_fd, &fds);
          fprintf(stderr, "user connect using fd %d\n", conn_fd);
        }
        else {
          conn_fd = i;
          
          cnline_protocol_header req, res;
          memset(&req, 0, sizeof(req));
          if (!recv(conn_fd, &req, sizeof(req), MSG_WAITALL)) {
            FD_CLR(i, &fds);
            close(i);
            fprintf(stderr, "fd %d end of connection\n", i);
            continue;
          }
          
          if (req.magic != CNLINE_PROTOCOL_MAGIC_REQ) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = req.op;
            res.status = CNLINE_PROTOCOL_STATUS_FAIL;
            send(conn_fd, &res, sizeof(res), 0);
            fprintf(stderr, "unknown message\n");
            continue;
          }
          
          if (req.op == CNLINE_PROTOCOL_OP_SIGNUP) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_SIGNUP;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            signup(conn_fd);
          }
          else if (req.op == CNLINE_PROTOCOL_OP_LOGIN) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_LOGIN;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            login(conn_fd);
          }
          else if (req.op == CNLINE_PROTOCOL_OP_MSG) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_MSG;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            msg(conn_fd);
          }
          else if (req.op == CNLINE_PROTOCOL_OP_FILE) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_FILE;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            file(conn_fd, &fds);
          }
          else if (req.op == CNLINE_PROTOCOL_OP_HISTORY) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_HISTORY;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            history(conn_fd);
          }
          else if (req.op == CNLINE_PROTOCOL_OP_LOGOUT) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_LOGOUT;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            logout(conn_fd);
          }
          else if (req.op == CNLINE_PROTOCOL_OP_REFRESH) {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = CNLINE_PROTOCOL_OP_REFRESH;
            res.status = CNLINE_PROTOCOL_STATUS_OK;
            send(conn_fd, &res, sizeof(res), 0);
            
            refresh(conn_fd);
          }
          else {
            memset(&res, 0, sizeof(res));
            res.magic = CNLINE_PROTOCOL_MAGIC_RES;
            res.op = req.op;
            res.status = CNLINE_PROTOCOL_STATUS_FAIL;
            send(conn_fd, &res, sizeof(res), 0);
            fprintf(stderr, "unknown message\n");
          }
        }
      }
    }
  }
  return 0;
}

static void signup(int conn_fd) {
  cnline_protocol_signup req;
  cnline_protocol_header res;
  memset(&req, 0, sizeof(req));
  recv(conn_fd, &req, sizeof(req), MSG_WAITALL);
  if (req.op != CNLINE_PROTOCOL_OP_SIGNUP) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_SIGNUP;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "unknown message\n");
    return;
  }
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t password[SHA256_DIGEST_LENGTH];
  memset(user, 0, sizeof(user));
  memset(password, 0, sizeof(password));
  memcpy(user, req.user, sizeof(user));
  memcpy(password, req.password, sizeof(password));
  
  struct stat stat;
  if (lstat(user, &stat) == 0) {
    if (S_ISDIR(stat.st_mode) != 0) {
      memset(&res, 0, sizeof(res));
      res.magic = CNLINE_PROTOCOL_MAGIC_RES;
      res.op = CNLINE_PROTOCOL_OP_SIGNUP;
      res.status = CNLINE_PROTOCOL_STATUS_FAIL;
      send(conn_fd, &res, sizeof(res), 0);
      fprintf(stderr, "%s already registered\n", user);
      return;
    }
    else {
      unlink(user);
    }
  }
  
  mkdir(user, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  
  char path[PATH_MAX];
  int fd;
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".password.sha256");
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  write(fd, password, sizeof(password));
  close(fd);
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".outbox");
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  close(fd);
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".inbox_unread");
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  close(fd);
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".inbox_read");
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  close(fd);
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".files");
  mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_SIGNUP;
  res.status = CNLINE_PROTOCOL_STATUS_OK;
  send(conn_fd, &res, sizeof(res), 0);
  fprintf(stderr, "%s signup success\n", user);
}

static void login(int conn_fd) {
  cnline_protocol_login req;
  cnline_protocol_header res;
  memset(&req, 0, sizeof(req));
  recv(conn_fd, &req, sizeof(req), MSG_WAITALL);
  if (req.op != CNLINE_PROTOCOL_OP_LOGIN) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_LOGIN;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "unknown message\n");
    return;
  }
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t password[SHA256_DIGEST_LENGTH];
  memset(user, 0, sizeof(user));
  memset(password, 0, sizeof(password));
  memcpy(user, req.user, sizeof(user));
  memcpy(password, req.password, sizeof(password));
  
  struct stat stat;
  if (lstat(user, &stat) < 0 || S_ISDIR(stat.st_mode) == 0) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_LOGIN;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s not exist\n", user);
    return;
  }
  
  uint8_t digest[SHA256_DIGEST_LENGTH];
  char path[PATH_MAX];
  int fd;
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".password.sha256");
  fd = open(path, O_RDONLY);
  read(fd, digest, sizeof(digest));
  close(fd);
  
  if (memcmp(password, digest, sizeof(password)) != 0) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_LOGIN;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "password hash not match\n");
    return;
  }
  
  uint8_t buf[sizeof(int) + sizeof(user)];
  strcpy(path, ".conn");
  if (lstat(path, &stat) == 0) {
    char tmp[] = ".tmp";
    int fd_tmp;
    
    fd = open(path, O_RDONLY);
    fd_tmp = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    ssize_t len;
    while (len = read(fd, buf, sizeof(buf))) {
      if (len < sizeof(buf)) {
        break;
      }
      if (memcmp(buf, &conn_fd, sizeof(int)) != 0 && 
      memcmp(buf + sizeof(int), user, sizeof(user)) != 0) {
        write(fd_tmp, buf, sizeof(buf));
      }
    }
    close(fd);
    close(fd_tmp);
    unlink(path);
    rename(tmp, path);
  }
  
  fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  memcpy(buf, &conn_fd, sizeof(int));
  memcpy(buf + sizeof(int), user, sizeof(user));
  write(fd, buf, sizeof(buf));
  close(fd);
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_LOGIN;
  res.status = CNLINE_PROTOCOL_STATUS_OK;
  send(conn_fd, &res, sizeof(res), 0);
  fprintf(stderr, "%s login success\n", user);
}

static void msg(int conn_fd) {
  cnline_protocol_msg req;
  cnline_protocol_header res;
  memset(&req, 0, sizeof(req));
  recv(conn_fd, &req, sizeof(req), MSG_WAITALL);
  if (req.op != CNLINE_PROTOCOL_OP_MSG) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_MSG;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "unknown message\n");
    return;
  }
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t buf[sizeof(int) + sizeof(user)];
  int fd;
  ssize_t len;
  fd = open(".conn", O_RDONLY);
  while (len = read(fd, buf, sizeof(buf))) {
    if (len < sizeof(buf)) {
      break;
    }
    if (memcmp(buf, &conn_fd, sizeof(int)) == 0) {
      memcpy(user, buf + sizeof(int), sizeof(user));
      break;
    }
  }
  close(fd);
  
  struct stat stat;
  
  uint8_t touser[CNLINE_LIMIT_USERLEN];
  uint8_t content[CNLINE_LIMIT_MSGLEN];
  memset(touser, 0, sizeof(touser));
  memset(content, 0, sizeof(content));
  memcpy(touser, req.touser, sizeof(touser));
  memcpy(content, req.content, sizeof(content));
  
  if (lstat(touser, &stat) < 0 || S_ISDIR(stat.st_mode) == 0) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_MSG;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s not exist\n", touser);
    return;
  }
  
  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  char path[PATH_MAX];
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".outbox");
  fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  write(fd, &tv, sizeof(tv));
  write(fd, touser, sizeof(touser));
  write(fd, content, sizeof(content));
  close(fd);
  
  
  strcpy(path, touser);
  strcat(path, "/");
  strcat(path, ".inbox_unread");
  fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  write(fd, &tv, sizeof(tv));
  write(fd, user, sizeof(user));
  write(fd, content, sizeof(content));
  close(fd);
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_MSG;
  res.status = CNLINE_PROTOCOL_STATUS_OK;
  send(conn_fd, &res, sizeof(res), 0);
  fprintf(stderr, "%s send msg to %s success\n", user, touser);
}

static void file(int conn_fd, fd_set* fds) {
  cnline_protocol_file req;
  cnline_protocol_header res;
  memset(&req, 0, sizeof(req));
  recv(conn_fd, &req, sizeof(req), MSG_WAITALL);
  if (req.op != CNLINE_PROTOCOL_OP_FILE) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_FILE;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "unknown message\n");
    return;
  }
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t buf[sizeof(int) + sizeof(user)];
  int fd;
  ssize_t len;
  fd = open(".conn", O_RDONLY);
  while (len = read(fd, buf, sizeof(buf))) {
    if (len < sizeof(buf)) {
      break;
    }
    if (memcmp(buf, &conn_fd, sizeof(int)) == 0) {
      memcpy(user, buf + sizeof(int), sizeof(user));
      break;
    }
  }
  close(fd);
  
  struct stat stat;
  
  uint8_t touser[CNLINE_LIMIT_USERLEN];
  memset(touser, 0, sizeof(touser));
  memcpy(touser, req.touser, sizeof(touser));
  
  if (lstat(touser, &stat) < 0 || S_ISDIR(stat.st_mode) == 0) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_FILE;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    res.reserved = CNLINE_PROTOCOL_OP_SIGNUP;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s not exist\n", touser);
    return;
  }
  
  int tofd = -1;
  
  fd = open(".conn", O_RDONLY);
  while (len = read(fd, buf, sizeof(buf))) {
    if (len < sizeof(buf)) {
      break;
    }
    if (memcmp(buf + sizeof(int), touser, sizeof(user)) == 0) {
      memcpy(&tofd, buf, sizeof(int));
      break;
    }
  }
  close(fd);
  
  if (tofd == -1 || !FD_ISSET(tofd, fds)) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_FILE;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    res.reserved = CNLINE_PROTOCOL_OP_LOGOUT;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s not login\n", touser);
    return;
  }
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_FILE;
  res.status = CNLINE_PROTOCOL_STATUS_OK;
  send(conn_fd, &res, sizeof(res), 0);
  
  char path[PATH_MAX];
  char filename[PATH_MAX];
  recv(conn_fd, filename, req.pathlen, MSG_WAITALL);
  filename[req.pathlen] = '\0';
  strcpy(path, touser);
  strcat(path, "/");
  strcat(path, ".files");
  strcat(path, "/");
  strcat(path, basename(filename));
  
  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  uint8_t* tvptr = (uint8_t*) &tv;
  uint8_t tvbuf[sizeof(tv) * 2 + 1];
  int i;
  for (i = 0; i < sizeof(tv); i++) {
    sprintf(tvbuf + i * 2, "%02x", tvptr[i]);
  }
  tvbuf[sizeof(tv) * 2 + 1] = '\0';
  
  strcat(path, ".");
  strcat(path, tvbuf);
  
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  
  write(fd, user, sizeof(user));
  
  uint8_t databuf[BUFSIZ];
  ssize_t remain = (ssize_t) req.datalen;
  ssize_t readlen;
  while (remain) {
    readlen = (remain < sizeof(databuf)) ? remain : sizeof(databuf);
    len = recv(conn_fd, databuf, readlen, MSG_WAITALL);
    if (!len) {
      break;
    }
    write(fd, databuf, len);
    remain -= len;
  }
  close(fd);
  fprintf(stderr, "%s send %s to %s\n", user, basename(filename), touser);
}

static void history(int conn_fd) {
  cnline_protocol_history req;
  cnline_protocol_header res;
  memset(&req, 0, sizeof(req));
  recv(conn_fd, &req, sizeof(req), MSG_WAITALL);
  if (req.op != CNLINE_PROTOCOL_OP_HISTORY) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_HISTORY;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "unknown message\n");
    return;
  }
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t buf[sizeof(int) + sizeof(user)];
  int fd, fd2;
  ssize_t len;
  fd = open(".conn", O_RDONLY);
  while (len = read(fd, buf, sizeof(buf))) {
    if (len < sizeof(buf)) {
      break;
    }
    if (memcmp(buf, &conn_fd, sizeof(int)) == 0) {
      memcpy(user, buf + sizeof(int), sizeof(user));
      break;
    }
  }
  close(fd);
  
  struct stat stat, stat2;
  uint8_t touser[CNLINE_LIMIT_USERLEN];
  memset(touser, 0, sizeof(touser));
  memcpy(touser, req.touser, sizeof(touser));
  
  if (lstat(touser, &stat) < 0 || S_ISDIR(stat.st_mode) == 0) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_HISTORY;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s not exist\n", touser);
    return;
  }
  
  char path[PATH_MAX];
  char path2[PATH_MAX];
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".outbox");
  lstat(path, &stat);
  
  strcpy(path2, user);
  strcat(path2, "/");
  strcat(path2, ".inbox_read");
  lstat(path2, &stat2);
  
  if (!stat.st_size && !stat2.st_size) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_HISTORY;
    res.status = CNLINE_PROTOCOL_STATUS_OK;
    res.reserved = CNLINE_PROTOCOL_OP_MSG;
    res.followlen = 0;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "no message between %s and %s\n", user, touser);
    return;
  }
  
  char tmp[] = ".tmp";
  
  fd = open(path, O_RDONLY);
  fd2 = open(path2, O_RDONLY);
  
  int fd_tmp = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  
  ssize_t remain, remain2;
  remain = stat.st_size;
  remain2 = stat2.st_size;
  
  struct timeval tv, tv2;
  uint8_t userbuf[CNLINE_LIMIT_USERLEN], userbuf2[CNLINE_LIMIT_USERLEN];
  uint8_t content[CNLINE_LIMIT_MSGLEN], content2[CNLINE_LIMIT_MSGLEN];
  
  uint8_t msgbuf[sizeof(tv) + sizeof(userbuf) + sizeof(content)];
  uint8_t msgbuf2[sizeof(tv2) + sizeof(userbuf2) + sizeof(content2)];
  
  int next = 3;
  while (remain || remain2) {
    if (remain && next & 1) {
      read(fd, msgbuf, sizeof(msgbuf));
      memcpy(&tv, msgbuf, sizeof(tv));
      memcpy(msgbuf + sizeof(tv), user, sizeof(user));
    }
    
    if (remain2 && next & 2) {
      read(fd2, msgbuf2, sizeof(msgbuf2));
      memcpy(&tv2, msgbuf2, sizeof(tv2));
    }
    
    if (!remain && remain2) {
      write(fd_tmp, msgbuf2, sizeof(msgbuf2));
      remain2 -= sizeof(msgbuf2);
      next = 1;
    }
    else if (remain && !remain2) {
      write(fd_tmp, msgbuf, sizeof(msgbuf));
      remain -= sizeof(msgbuf);
      next = 2;
    }
    else if (tv.tv_sec < tv2.tv_sec) {
      write(fd_tmp, msgbuf, sizeof(msgbuf));
      remain -= sizeof(msgbuf);
      next = 2;
    }
    else if (tv.tv_sec >= tv2.tv_sec) {
      write(fd_tmp, msgbuf2, sizeof(msgbuf2));
      remain2 -= sizeof(msgbuf2);
      next = 1;
    }
    else {
      break;
    }
  }
  
  close(fd);
  close(fd2);
  close(fd_tmp);
  
  lstat(tmp, &stat);
  if (!stat.st_size) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_HISTORY;
    res.status = CNLINE_PROTOCOL_STATUS_OK;
    res.reserved = CNLINE_PROTOCOL_OP_MSG;
    res.followlen = 0;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "no message between %s and %s\n", user, touser);
    return;
  }
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_HISTORY;
  res.status = CNLINE_PROTOCOL_STATUS_OK;
  res.reserved = CNLINE_PROTOCOL_OP_MSG;
  res.followlen = stat.st_size;
  send(conn_fd, &res, sizeof(res), 0);
  
  fd = open(tmp, O_RDONLY);
  uint8_t databuf[BUFSIZ];
  ssize_t readlen;
  remain = (ssize_t) res.followlen;
  
  while (remain) {
    readlen = (remain < sizeof(databuf)) ? remain : sizeof(databuf);
    len = read(fd, databuf, readlen);
    if (!len) {
      break;
    }
    send(conn_fd, databuf, len, 0);
    remain -= len;
  }
  
  close(fd);
  unlink(tmp);
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_HISTORY;
  res.status = CNLINE_PROTOCOL_STATUS_OK;
  send(conn_fd, &res, sizeof(res), 0);
  fprintf(stderr, "%s receive history message\n", user);
  return;
}

static void logout(int conn_fd) {
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t buf[sizeof(int) + sizeof(user)];
  int fd;
  ssize_t len;
  fd = open(".conn", O_RDONLY);
  while (len = read(fd, buf, sizeof(buf))) {
    if (len < sizeof(buf)) {
      break;
    }
    if (memcmp(buf, &conn_fd, sizeof(int)) == 0) {
      memcpy(user, buf + sizeof(int), sizeof(user));
      break;
    }
  }
  close(fd);
  
  fprintf(stderr, "%s logout\n", user);
}

static void refresh(int conn_fd) {
  cnline_protocol_refresh req;
  cnline_protocol_header res;
  memset(&req, 0, sizeof(req));
  recv(conn_fd, &req, sizeof(req), MSG_WAITALL);
  if (req.op != CNLINE_PROTOCOL_OP_REFRESH) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_REFRESH;
    res.status = CNLINE_PROTOCOL_STATUS_FAIL;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "unknown message\n");
    return;
  }
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t buf[sizeof(int) + sizeof(user)];
  int fd;
  ssize_t len;
  fd = open(".conn", O_RDONLY);
  while (len = read(fd, buf, sizeof(buf))) {
    if (len < sizeof(buf)) {
      break;
    }
    if (memcmp(buf, &conn_fd, sizeof(int)) == 0) {
      memcpy(user, buf + sizeof(int), sizeof(user));
      break;
    }
  }
  close(fd);
  
  struct stat stat;
  char path[PATH_MAX];
  char path2[PATH_MAX];
  uint8_t databuf[BUFSIZ];
  ssize_t remain, readlen;
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".inbox_unread");
  lstat(path, &stat);
  if (stat.st_size) {
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_REFRESH;
    res.status = CNLINE_PROTOCOL_STATUS_OK;
    res.reserved = CNLINE_PROTOCOL_OP_MSG;
    res.followlen = stat.st_size;
    send(conn_fd, &res, sizeof(res), 0);
    
    strcpy(path2, user);
    strcat(path2, "/");
    strcat(path2, ".inbox_read");
    
    fd = open(path, O_RDONLY);
    int fd2 = open(path2, O_WRONLY | O_APPEND);
    
    remain = (ssize_t) res.followlen;
    while (remain) {
      readlen = (remain < sizeof(databuf)) ? remain : sizeof(databuf);
      len = read(fd, databuf, readlen);
      if (!len) {
        break;
      }
      send(conn_fd, databuf, len, 0);
      write(fd2, databuf, len);
      remain -= len;
    }
    
    close(fd);
    fd = open(path, O_WRONLY | O_TRUNC);
    close(fd);
    close(fd2);
    
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_REFRESH;
    res.status = CNLINE_PROTOCOL_STATUS_OK;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s receive messages\n", user);
    return;
  }
  
  strcpy(path, user);
  strcat(path, "/");
  strcat(path, ".files");
  DIR* dir = opendir(path);
  struct dirent* dp;
  char tmp[PATH_MAX];
  while ((dp = readdir(dir)) != NULL) {
    if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
      strcat(path, "/");
      strcat(path, dp->d_name);
      lstat(path, &stat);
      if (S_ISREG(stat.st_mode) == 0) {
        continue;
      }
      
      memset(&res, 0, sizeof(res));
      res.magic = CNLINE_PROTOCOL_MAGIC_RES;
      res.op = CNLINE_PROTOCOL_OP_REFRESH;
      res.status = CNLINE_PROTOCOL_STATUS_OK;
      res.reserved = CNLINE_PROTOCOL_OP_FILE;
      send(conn_fd, &res, sizeof(res), 0);
      
      strcpy(tmp, path);
      break;
    }
  }
  closedir(dir);
  
  if (dp != NULL) {
    cnline_protocol_file file;
    memset(&file, 0, sizeof(file));
    file.op = CNLINE_PROTOCOL_OP_REFRESH;
    path[strlen(path) - 2 * sizeof(struct timeval) - 1] = '\0';
    rename(tmp, path);
    fd = open(path, O_RDONLY);
    read(fd, file.touser, sizeof(file.touser));
    file.pathlen = strlen(basename(path));
    file.datalen = stat.st_size - sizeof(file.touser);
    send(conn_fd, &file, sizeof(file), 0);
    
    send(conn_fd, basename(path), file.pathlen, 0);
    
    recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
    if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
      close(fd);
      unlink(path);
      return;
    }
    
    remain = (ssize_t) file.datalen;
    while (remain) {
      readlen = (remain < sizeof(databuf)) ? remain : sizeof(databuf);
      len = read(fd, databuf, readlen);
      if (!len) {
        break;
      }
      send(conn_fd, databuf, len, 0);
      remain -= len;
    }
    
    close(fd);
    unlink(path);
    
    memset(&res, 0, sizeof(res));
    res.magic = CNLINE_PROTOCOL_MAGIC_RES;
    res.op = CNLINE_PROTOCOL_OP_REFRESH;
    res.status = CNLINE_PROTOCOL_STATUS_OK;
    send(conn_fd, &res, sizeof(res), 0);
    fprintf(stderr, "%s receive files\n", user);
    return;
  }
  
  memset(&res, 0, sizeof(res));
  res.magic = CNLINE_PROTOCOL_MAGIC_RES;
  res.op = CNLINE_PROTOCOL_OP_REFRESH;
  res.status = CNLINE_PROTOCOL_STATUS_FAIL;
  send(conn_fd, &res, sizeof(res), 0);
}
