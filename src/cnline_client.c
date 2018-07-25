#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <limits.h>
#include <libgen.h>
#include <locale.h>
#include <time.h>

#include "cnline_protocol.h"

#define TEXT_RED "\x1B[31m"
#define TEXT_RESET "\x1B[0m"

static int signup(int conn_fd, const uint8_t* user, const uint8_t* digest);
static int login(int conn_fd, const uint8_t* user, const uint8_t* digest);
static int msg(int conn_fd, const uint8_t* touser, const uint8_t* content);
static int file(int conn_fd, const uint8_t* touser, const uint8_t* filepath);
static int history(int conn_fd, const uint8_t* touser);
static void logout(int conn_fd);
static int refresh(int conn_fd);

int global_conn_fd;
int mutex = 0;

void sighdler(int signo) {
  if (!mutex) {
    mutex = 1;
    refresh(global_conn_fd);
    mutex = 0;
  }
}

char getchinv(int all) {
    struct termios oldtc, newtc;
    char c;
    tcgetattr(STDIN_FILENO, &oldtc);
    newtc = oldtc;
    newtc.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newtc);
    c = getchar();
    if (!all) {
      while (c == '\x1B') {
        char end[] = "ABCDPQRS~";
        int quit = 0;
        size_t i;
        while (!quit) {
          c = getchar();
          for (i = 0; i < strlen(end); i++) {
            if (c == end[i]) {
              quit = 1;
              break;
            }
          }
        }
        c = getchar();
      }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldtc);
    return c;
}

int scanword(char* s, const char stop, size_t min, size_t max, int inv) {
  char buf[4096];
  memset(buf, '\0', sizeof(buf));
  char c;
  size_t i = 0;
  while (1) {
    if (inv) {
      c = getchinv(0);
      if (c == '\b' || c == '\x7F') {
        if (i > 0) {
          i--;
        }
        buf[i] = '\0';
        continue;
      }
    }
    else {
      c = getchar();
    }
    if (c == stop) {
      break;
    }
    buf[i] = c;
    i++;
  }
  buf[i] = '\0';
  size_t len = strlen(buf);
  if (len >= min && len <= max) {
    strncpy(s, buf, max + 1);
    return 1;
  }
  else {
    memset(s, '\0', max + 1);
    return 0;
  }
}

int checkword(const char* s, const char* cond) {
  size_t len = strlen(s);
  size_t i;
  if (strcmp(cond, "ALNUM") == 0) {
    for (i = 0; i < len; i++) {
      if (!isalnum(s[i])) {
        return 0;
      }
    }
    return 1;
  }
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: ./cnline_client [.info]\n");
    return 0;
  }
  FILE* fp = fopen(argv[1], "r");
  if (fp == NULL) {
    fprintf(stderr, "'%s' cannot open\n", argv[1]);
    return 0;
  }
  char client_dir[PATH_MAX];
  if (!fscanf(fp, "client_dir=%s", client_dir)) {
    fprintf(stderr, ".info usage: client_dir=[path]\n");
    return 0;
  }
  fclose(fp);
  struct stat stat;
  if (lstat(client_dir, &stat) < 0) {
    mkdir(client_dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  }
  if (chdir(client_dir) < 0) {
    fprintf(stderr, "cannot change to %s directory\n", client_dir);
    return 0;
  }
  
  struct hostent* host;
  struct sockaddr_in dest;
  char ip[30];
  int conn_fd;
  
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t password1[CNLINE_LIMIT_PASSWORDLEN];
  uint8_t password2[CNLINE_LIMIT_PASSWORDLEN];
  uint8_t touser[CNLINE_LIMIT_USERLEN];
  uint8_t content[CNLINE_LIMIT_MSGLEN];
  uint8_t digest[SHA256_DIGEST_LENGTH];
  uint8_t filepath[PATH_MAX];
  uint8_t c;
  
  conn_fd = socket(AF_INET, SOCK_STREAM, 0);
  host = gethostbyname(CNLINE_SERVER_IP);
  strcpy(ip, inet_ntoa(*(struct in_addr*) host->h_addr));
  
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr(ip);
  dest.sin_port = htons(CNLINE_SERVER_PORT);
  
  if (connect(conn_fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_in))) {
    fprintf(stderr, "cannot connect to CNLine server\n");
    return 0;
  }
  
  
  puts("Welcome to CNLine.");
  
  setlocale(LC_ALL, "");
  global_conn_fd = conn_fd;
  signal(SIGUSR1, sighdler);
  
  while (1) {
    printf("Press (S)Signup (L)Login (E)Exit\n");
    c = getchinv(0);
    if (toupper(c) == 'S') {
      printf("Username [0-9A-Za-z]{1,15}: ");
      if (!scanword(user, '\n', 1, sizeof(user) - 1, 0) || 
      !checkword(user, "ALNUM")) {
        printf(TEXT_RED "Illegal username\n" TEXT_RESET);
        continue;
      }
      printf("Password [0-9A-Za-z]{6,15}: ");
      if (!scanword(password1, '\n', 6, sizeof(password1) - 1, 1) || 
      !checkword(password1, "ALNUM")) {
        printf("\n");
        printf(TEXT_RED "Illegal password\n" TEXT_RESET);
        continue;
      }
      printf("\n");
      printf("Confirm Password : ");
      if (!scanword(password2, '\n', 6, sizeof(password2) - 1, 1) || 
      !checkword(password2, "ALNUM") || 
      strncmp(password1, password2, sizeof(password1)) != 0) {
        printf("\n");
        printf(TEXT_RED "Password not match\n" TEXT_RESET);
        continue;
      }
      printf("\n");
      memset(&digest, 0, sizeof(digest));
      SHA256(password1, strlen(password1), digest);
      if (signup(conn_fd, user, digest)) {
        printf("signup success\n");
      }
      else {
        printf("signup fail\n");
      }
    }
    else if (toupper(c) == 'L') {
      printf("Username : ");
      if (!scanword(user, '\n', 1, sizeof(user) - 1, 0) || 
      !checkword(user, "ALNUM")) {
        printf(TEXT_RED "Illegal username\n" TEXT_RESET);
        continue;
      }
      printf("Password [0-9A-Za-z]{6,15}: ");
      if (!scanword(password1, '\n', 6, sizeof(password1) - 1, 1) || 
      !checkword(password1, "ALNUM")) {
        printf("\n");
        printf(TEXT_RED "Illegal password\n" TEXT_RESET);
        continue;
      }
      printf("\n");
      memset(&digest, 0, sizeof(digest));
      SHA256(password1, strlen(password1), digest);
      if (login(conn_fd, user, digest)) {
        printf("login success\n");
      }
      else {
        printf("login fail\n");
        continue;
      }
      pid_t pid = 0;
      while (1) {
        printf("Press (M)Messaging (F)send File (H)History (L)Logout\n");
        if (pid == 0) {
          pid = fork();
        }
        if (pid == 0) {
          while (1) {
            kill(getppid(), SIGUSR1);
            sleep(3);
          }
        }
        c = getchinv(0);
        if (toupper(c) == 'M') {
          printf("Message to: ");
          if (!scanword(touser, '\n', 1, sizeof(touser) - 1, 0) || 
          !checkword(touser, "ALNUM")) {
            printf(TEXT_RED "Illegal username\n" TEXT_RESET);
            continue;
          }
          printf("Press (Ctrl+S)Send\n");
          printf("Content (1-63 words):\n");
          if (!scanword(content, '\n', 1, sizeof(content) - 1, 0)) {
            printf(TEXT_RED "Illegal content\n" TEXT_RESET);
          }
          printf("Confirm to send message to %s? (Y)Yes (N)No\n", touser);
          while (1) {
            c = getchinv(0);
            if (toupper(c) == 'Y') {
              if (msg(conn_fd, touser, content)) {
                printf("send message success\n");
              }
              else {
                printf(TEXT_RED "User %s not exist\n" TEXT_RESET, touser);
              }
              break;
            }
            else if (toupper(c) == 'N') {
              printf("Message discard\n");
              break;
            }
          }
        }
        else if (toupper(c) == 'F') {
          printf("Send file to: ");
          if (!scanword(touser, '\n', 1, sizeof(touser) - 1, 0) || 
          !checkword(touser, "ALNUM")) {
            printf(TEXT_RED "Illegal username\n" TEXT_RESET);
            continue;
          }
          printf("Choose your file\n");
          if (!scanword(filepath, '\n', 1, 100, 0) || 
          lstat(filepath, &stat) < 0 || S_ISREG(stat.st_mode) == 0) {
            printf(TEXT_RED "Illegal filepath\n" TEXT_RESET);
            continue;
          }
          printf("Confirm to send file '%s' (%'llu Bytes) to %s? (Y)Yes (N)No\n", filepath, (uint64_t) stat.st_size, touser);
          while (1) {
            c = getchinv(0);
            if (toupper(c) == 'Y') {
              if (file(conn_fd, touser, filepath)) {
                printf("send file success\n");
              }
              else {
                printf(TEXT_RED "send file fail\n" TEXT_RESET);
              }
              break;
            }
            else if (toupper(c) == 'N') {
              printf("Sending discard\n");
              break;
            }
          }
        }
        else if (toupper(c) == 'H') {
          printf("user want to lookup: ");
          if (!scanword(touser, '\n', 1, sizeof(touser) - 1, 0) || 
          !checkword(touser, "ALNUM")) {
            printf(TEXT_RED "Illegal username\n" TEXT_RESET);
            continue;
          }
          if (!history(conn_fd, touser)) {
            printf("user %s not exist\n", touser);
          }
        }
        else if (toupper(c) == 'L') {
          printf("Confirm to logout? (Y)Yes (N)No\n");
          while (1) {
            c = getchinv(0);
            if (toupper(c) == 'Y') {
              logout(conn_fd);
              kill(pid, SIGTERM);
              pid = 0;
              break;
            }
            else if (toupper(c) == 'N') {
              break;
            }
          }
          if (toupper(c) == 'Y') {
            break;
          }
        }
      }
    }
    else if (toupper(c) == 'E') {
      break;
    }
  }
  puts("Bye. Press to continue...");
  getchinv(1);
  return 0;
}

static int signup(int conn_fd, const uint8_t* user, const uint8_t* password) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_SIGNUP;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  cnline_protocol_signup signup;
  signup.op = CNLINE_PROTOCOL_OP_SIGNUP;
  memcpy(signup.user, user, sizeof(signup.user));
  memcpy(signup.password, password, sizeof(signup.password));
  send(conn_fd, &signup, sizeof(signup), 0);
  
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status == CNLINE_PROTOCOL_STATUS_OK) {
    return 1;
  }
  else {
    return 0;
  }
}

static int login(int conn_fd, const uint8_t* user, const uint8_t* password) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_LOGIN;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  cnline_protocol_login login;
  login.op = CNLINE_PROTOCOL_OP_LOGIN;
  memcpy(login.user, user, sizeof(login.user));
  memcpy(login.password, password, sizeof(login.password));
  send(conn_fd, &login, sizeof(login), 0);
  
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status == CNLINE_PROTOCOL_STATUS_OK) {
    return 1;
  }
  else {
    return 0;
  }
}

static int msg(int conn_fd, const uint8_t* touser, const uint8_t* content) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_MSG;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  cnline_protocol_msg msg;
  msg.op = CNLINE_PROTOCOL_OP_MSG;
  memcpy(msg.touser, touser, sizeof(msg.touser));
  memcpy(msg.content, content, sizeof(msg.content));
  send(conn_fd, &msg, sizeof(msg), 0);
  
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status == CNLINE_PROTOCOL_STATUS_OK) {
    return 1;
  }
  else {
    return 0;
  }
}

static int file(int conn_fd, const uint8_t* touser, const uint8_t* filepath) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_FILE;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    if (res.reserved == CNLINE_PROTOCOL_OP_SIGNUP) {
      printf(TEXT_RED "user %s not exist, " TEXT_RESET, touser);
    }
    else if (res.reserved == CNLINE_PROTOCOL_OP_LOGOUT) {
      printf(TEXT_RED "user %s not online, " TEXT_RESET, touser);
    }
    return 0;
  }
  
  struct stat stat;
  lstat(filepath, &stat);
  
  uint8_t* basepath = (uint8_t*) basename((char*) filepath);
  
  cnline_protocol_file file;
  file.op = CNLINE_PROTOCOL_OP_FILE;
  memcpy(file.touser, touser, sizeof(file.touser));
  file.pathlen = (uint16_t) strlen(basepath);
  file.datalen = (uint64_t) stat.st_size;
  send(conn_fd, &file, sizeof(file), 0);
  
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  send(conn_fd, basepath, file.pathlen, 0);
  
  int fd = open(filepath, O_RDONLY);
  uint8_t buf[BUFSIZ];
  ssize_t len;
  ssize_t remain = (ssize_t) file.datalen;
  ssize_t readlen;
  while (remain) {
    readlen = (remain < sizeof(buf)) ? remain : sizeof(buf);
    len = read(fd, buf, readlen);
    if (!len) {
      break;
    }
    send(conn_fd, buf, len, 0);
    remain -= len;
  }
  
  if (res.status == CNLINE_PROTOCOL_STATUS_OK) {
    return 1;
  }
  else {
    return 0;
  }
}

static int history(int conn_fd, const uint8_t* touser) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_HISTORY;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  cnline_protocol_history history;
  history.op = CNLINE_PROTOCOL_OP_HISTORY;
  memcpy(history.touser, touser, sizeof(history.touser));
  send(conn_fd, &history, sizeof(history), 0);
  
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  printf("b\n");
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  if (res.reserved != CNLINE_PROTOCOL_OP_MSG) {
    return 0;
  }
  
  if (!res.followlen) {
    printf("no messages between you and %s\n", touser);
    return 1;
  }
  
  struct timeval tv;
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t content[CNLINE_LIMIT_MSGLEN];
  
  struct tm* ptm;
  char timestr[200];
  
  printf("\n====================History====================\n");
  ssize_t remain = (ssize_t) res.followlen;
  while (remain) {
    recv(conn_fd, &tv, sizeof(tv), MSG_WAITALL);
    recv(conn_fd, user, sizeof(user), MSG_WAITALL);
    recv(conn_fd, content, sizeof(content), MSG_WAITALL);
    
    ptm = localtime(&tv.tv_sec);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ptm);
    printf("%s  ", timestr);
    printf("%s: %s\n", user, content);
    
    remain -= sizeof(tv) + sizeof(user) + sizeof(content);
  }
  printf("===============================================\n");
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  return 1;
}

static void logout(int conn_fd) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_LOGOUT;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  return;
}

static int refresh(int conn_fd) {
  cnline_protocol_header req, res;
  memset(&req, 0, sizeof(req));
  req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
  req.op = CNLINE_PROTOCOL_OP_REFRESH;
  send(conn_fd, &req, sizeof(req), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  cnline_protocol_refresh refresh;
  refresh.op = CNLINE_PROTOCOL_OP_REFRESH;
  send(conn_fd, &refresh, sizeof(refresh), 0);
  recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
  if (res.status != CNLINE_PROTOCOL_STATUS_OK) {
    return 0;
  }
  
  char path[PATH_MAX];
  uint8_t databuf[BUFSIZ];
  ssize_t len, remain, readlen;
  int fd;
  
  struct timeval tv;
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t content[CNLINE_LIMIT_MSGLEN];
  
  struct stat stat;
  char c;
  
  struct tm* ptm;
  char timestr[200];
  
  if (res.reserved == CNLINE_PROTOCOL_OP_MSG) {
    printf("\n====================received message====================\n");
    remain = (ssize_t) res.followlen;
    while (remain) {
      recv(conn_fd, &tv, sizeof(tv), MSG_WAITALL);
      recv(conn_fd, user, sizeof(user), MSG_WAITALL);
      recv(conn_fd, content, sizeof(content), MSG_WAITALL);
      
      ptm = localtime(&tv.tv_sec);
      strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ptm);
      printf("%s\n", timestr);
      printf("  %s: %s\n", user, content);
      printf("\n");
      
      remain -= sizeof(tv) + sizeof(user) + sizeof(content);
    }
    printf("========================================================\n");
    recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
    printf("Press to continue\n");
    getchinv(0);
  }
  else if (res.reserved == CNLINE_PROTOCOL_OP_FILE) {
    cnline_protocol_file file;
    recv(conn_fd, &file, sizeof(file), MSG_WAITALL);
    recv(conn_fd, path, file.pathlen, MSG_WAITALL);
    path[file.pathlen] = '\0';
    printf("\n");
    printf("%s want to send file '%s' (%llu Bytes) to you, Accpet it? (Y)Yes (N)No\n", 
    file.touser, path, file.datalen);
    while (1) {
      c = getchinv(0);
      if (toupper(c) == 'Y') {
        memset(&req, 0, sizeof(req));
        req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
        req.op = CNLINE_PROTOCOL_OP_REFRESH;
        req.status = CNLINE_PROTOCOL_STATUS_OK;
        send(conn_fd, &req, sizeof(req), 0);
        
        char tmp[] = ".tmp";
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        
        remain = (ssize_t) file.datalen;
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
        
        recv(conn_fd, &res, sizeof(res), MSG_WAITALL);
        
        if (lstat(path, &stat) == 0) {
          char* dot;
          dot = strrchr(path, '.');
          if (dot == NULL) {
            strcat(path, "(new)");
          }
          else {
            char tmp2[PATH_MAX];
            strcpy(tmp2, dot);
            *dot = '\0';
            strcat(path, "(new)");
            strcat(path, tmp2);
          }
        }
        rename(tmp, path);
        printf("received file %s from %s\n", path, file.touser);
        printf("Press to continue\n");
        getchinv(0);
        break;
      }
      else if (toupper(c) == 'N') {
        memset(&req, 0, sizeof(req));
        req.magic = CNLINE_PROTOCOL_MAGIC_REQ;
        req.op = CNLINE_PROTOCOL_OP_REFRESH;
        req.status = CNLINE_PROTOCOL_STATUS_FAIL;
        send(conn_fd, &req, sizeof(req), 0);
        break;
      }
    }
  }
  return 1;
}
