#include <stdint.h>
#include <openssl/sha.h>

#define CNLINE_SERVER_IP "127.0.0.1"
#define CNLINE_SERVER_PORT 2501

#define CNLINE_LIMIT_USERLEN 16
#define CNLINE_LIMIT_PASSWORDLEN 16
#define CNLINE_LIMIT_MSGLEN 64

typedef enum {
  CNLINE_PROTOCOL_MAGIC_REQ = 0x01,
  CNLINE_PROTOCOL_MAGIC_RES = 0x02,
} cnline_protocol_magic;

typedef enum {
  CNLINE_PROTOCOL_OP_SIGNUP = 0x01,
  CNLINE_PROTOCOL_OP_LOGIN = 0x02,
  CNLINE_PROTOCOL_OP_MSG = 0x03,
  CNLINE_PROTOCOL_OP_FILE = 0x04,
  CNLINE_PROTOCOL_OP_LOGOUT = 0x05,
  CNLINE_PROTOCOL_OP_REFRESH = 0x06,
  CNLINE_PROTOCOL_OP_HISTORY = 0x07,
  CNLINE_PROTOCOL_OP_END = 0xFF,
} cnline_protocol_op;

typedef enum {
  CNLINE_PROTOCOL_STATUS_OK = 0x01,
  CNLINE_PROTOCOL_STATUS_FAIL = 0x02,
} cnline_protocol_status;

typedef struct {
  uint8_t magic;
  uint8_t op;
  uint8_t status;
  uint8_t reserved;
  uint64_t followlen;
} cnline_protocol_header;

typedef struct {
  uint8_t op;
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t password[SHA256_DIGEST_LENGTH];
} cnline_protocol_signup;

typedef struct {
  uint8_t op;
  uint8_t user[CNLINE_LIMIT_USERLEN];
  uint8_t password[SHA256_DIGEST_LENGTH];
} cnline_protocol_login;

typedef struct {
  uint8_t op;
  uint8_t touser[CNLINE_LIMIT_USERLEN];
  uint8_t content[CNLINE_LIMIT_MSGLEN];
} cnline_protocol_msg;

typedef struct {
  uint8_t op;
  uint8_t touser[CNLINE_LIMIT_USERLEN];
  uint16_t pathlen;
  uint64_t datalen;
} cnline_protocol_file;

typedef struct {
  uint8_t op;
} cnline_protocol_refresh;

typedef struct {
  uint8_t op;
  uint8_t touser[CNLINE_LIMIT_USERLEN];
} cnline_protocol_history;

typedef struct {
  uint8_t op;
} cnline_protocol_end;
