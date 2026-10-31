/* Host-only coverage of the SAME parser used inside the Android detector. */
#define main historical_main
#include "../test_observability_signature.c"
#undef main
#include "signature.h"
int main(void)
{
    uint64_t rng = 0x123456789abcULL;
    const unsigned sizes[] = {4096, 16384, 65536};
    for (unsigned s=0;s<3;s++) {
        for (unsigned i=0;i<10000;i++) {
            struct kclf_priv_layout pl;
            struct kclf_prog result;
            struct candidate c;
            uint64_t abi=0x7000000000ULL+((next_random(&rng)&0xfffff)<<16), priv=abi+0x100000;
            random_layout(&pl,&rng);
            if(kclf_prog_build((u8 *)page,sizes[s],abi,priv,&pl,next_random(&rng),&result)||
               !recognize(page,sizes[s]/4,&c)||c.abi!=abi||c.priv!=priv||
               c.saved!=pl.saved||c.token!=pl.donetok||c.done!=pl.done) return 1;
            unsigned tail=(result.entry_off-4+result.length)/4-1;
            if(page[tail]!=0xd65f0200u) return 1;
            /* Historical compatibility is tested on an in-memory fixture;
             * the injector and its device artifact are never modified. */
            page[tail]=0xd61f0200u;
            if(!recognize(page,sizes[s]/4,&c)||c.abi!=abi||c.priv!=priv||
               c.saved!=pl.saved||c.token!=pl.donetok||c.done!=pl.done) return 1;
            page[tail]=0xd65f03c0u;
            if(recognize(page,sizes[s]/4,&c)) return 1;
        }
        printf("PASS size=%u ret_x16=10000 historical_br_x16=10000 wrong_register_rejected=10000\n",sizes[s]);
    }
    for(unsigned i=0;i<10000;i++) {
        struct candidate c;
        for(unsigned j=0;j<65536/4;j++)page[j]=(uint32_t)next_random(&rng);
        if(recognize(page,65536/4,&c))return 1;
    }
    puts("PASS randomized_negative=10000 matches=0");
    return 0;
}
