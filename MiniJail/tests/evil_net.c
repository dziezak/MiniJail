#include <sys/socket.h>
int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    return s < 0 ? 1 : 0;
}