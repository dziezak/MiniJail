#include <stdio.h>
int main() {
    FILE *f = fopen("/etc/passwd", "r");
    return f ? 0 : 1;
}