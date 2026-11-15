#include <cstdio>
#include <cstring>
#include "helpers/streambuf.h"
using namespace snort;
using namespace std;
int main(){
    const char exp[4096] = "ABC";
    ostreambuf_infl b;
    const int len = sizeof(exp) - 1;
    b.sputc('A');
    int n = b.sputn(exp, len);
    b.sputc('Z');
    auto act = b.data(); auto al = b.data_len();
    printf("n=%d al=%lld memcmp4097=%d a[0..6]=%c%c%c%c%c%c e[0..6]=%c%c%c%c%c%c tail=%c%c\n",
        n, (long long)al, memcmp(exp, act, 4097),
        act[0],act[1],act[2],act[3],act[4],act[5],
        exp[0],exp[1],exp[2],exp[3],exp[4],exp[5],
        act[4095], act[4096]);
    delete[] b.take_data();
    return 0;
}
