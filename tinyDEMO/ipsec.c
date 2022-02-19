#define _GNU_SOURCE
#include "common.h"

#include "invite.h"
#include "message.h"
#include "options.h"
#include "publish.h"
#include "register.h"
#include "subscribe.h"

#include "tsk_debug.h"
#include "../tinyIPSec/src/tipsec.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct plugin_linux_ipsec_ctx_s {
    TIPSEC_DECLARE_CTX;
    tipsec_ctx_t* pc_base;

    const char* addr_local;
    const char* addr_remote;
    unsigned char ik[TIPSEC_IK_LEN];
    unsigned char ck[TIPSEC_CK_LEN];
} plugin_linux_ipsec_ctx_t;

static tsk_object_t* _plugin_linux_ipsec_ctx_ctor(tsk_object_t * self, va_list * app)
{
    fprintf(stderr, "PHH-IPSec: Calling ctor\n");
    plugin_linux_ipsec_ctx_t *p_ctx = (plugin_linux_ipsec_ctx_t *)self;
    if (p_ctx) {
        p_ctx->pc_base = TIPSEC_CTX(p_ctx);
    }
    return self;
}

static tsk_object_t* _plugin_linux_ipsec_ctx_dtor(tsk_object_t * self)
{
    fprintf(stderr, "PHH-IPSec: Calling dtor\n");
    plugin_linux_ipsec_ctx_t *p_ctx = (plugin_linux_ipsec_ctx_t *)self;
    if (p_ctx) {
        if (p_ctx->pc_base->started) {
            tipsec_ctx_stop(p_ctx->pc_base);
        }

        TSK_FREE(p_ctx->pc_base->addr_local);
        TSK_FREE(p_ctx->pc_base->addr_remote);

        TSK_DEBUG_INFO("*** Linux IPSec plugin context destroyed ***");
    }

    return self;
}

static tipsec_error_t _plugin_linux_ipsec_ctx_init(tipsec_ctx_t* self) {
    fprintf(stderr, "PHH-IPSec: Calling init\n");
    plugin_linux_ipsec_ctx_t *s = (plugin_linux_ipsec_ctx_t *)self;
    TIPSEC_CTX(s)->initialized = tsk_true;
    TIPSEC_CTX(s)->state = tipsec_state_initial;
    //TIPSEC_CTX(s)->alg = tipsec_alg_hmac_sha_1_96;
    return tipsec_error_success;
}

static tipsec_error_t _plugin_linux_ipsec_ctx_set_local(tipsec_ctx_t* self, const char* addr_local, const char* addr_remote, tipsec_port_t port_uc, tipsec_port_t port_us) {
    fprintf(stderr, "PHH-IPSec: Calling set_local local:%s, remote:%s, port: %d, port: %d\n", addr_local, addr_remote, port_uc, port_us);
    plugin_linux_ipsec_ctx_t *s = (plugin_linux_ipsec_ctx_t *)self;
    TIPSEC_CTX(s)->state = tipsec_state_inbound;
    // Select random SPI
    getrandom(&(TIPSEC_CTX(s)->spi_uc), sizeof(TIPSEC_CTX(s)->spi_uc), 0);
    getrandom(&(TIPSEC_CTX(s)->spi_us), sizeof(TIPSEC_CTX(s)->spi_us), 0);
    TIPSEC_CTX(s)->port_uc = port_uc;
    TIPSEC_CTX(s)->port_us = port_us;
    s->addr_local = strdup(addr_local);
    s->addr_remote = strdup(addr_remote);
    return tipsec_error_success;
}

static tipsec_error_t _plugin_linux_ipsec_ctx_set_remote(tipsec_ctx_t* self, tipsec_spi_t spi_pc, tipsec_spi_t spi_ps, tipsec_port_t port_pc, tipsec_port_t port_ps, tipsec_lifetime_t lifetime) {
    plugin_linux_ipsec_ctx_t *s = (plugin_linux_ipsec_ctx_t *)self;
    fprintf(stderr, "PHH-IPSec: Calling set_remote spi pc:%d, spi ps: %d, port pc: %d, port ps: %d, lifetime: %ld\n", spi_pc, spi_ps, port_pc, port_ps, lifetime);
    TIPSEC_CTX(s)->spi_pc = spi_pc;
    TIPSEC_CTX(s)->spi_ps = spi_ps;
    TIPSEC_CTX(s)->port_pc = port_pc;
    TIPSEC_CTX(s)->port_ps = port_ps;
    return tipsec_error_success;
}

static tipsec_error_t _plugin_linux_ipsec_ctx_set_keys(tipsec_ctx_t* self, const tipsec_key_t* ik, const tipsec_key_t* ck) {
    fprintf(stderr, "PHH-IPSec: Calling set_keys, need to send stuff to ik and ck\n");
    plugin_linux_ipsec_ctx_t *s = (plugin_linux_ipsec_ctx_t *)self;
    TIPSEC_CTX(s)->state = tipsec_state_full;
    memcpy(s->ik, ik, TIPSEC_IK_LEN);
    memcpy(s->ck, ck, TIPSEC_IK_LEN);
    return tipsec_error_success;
}

static tipsec_error_t _plugin_linux_ipsec_ctx_start(tipsec_ctx_t* self) {
    fprintf(stderr, "PHH-IPSec: Calling start\n");
    plugin_linux_ipsec_ctx_t *s = (plugin_linux_ipsec_ctx_t *)self;
    char *auth_key = strdup("0x");
    for(int i=0; i<16;i++) {
        asprintf(&auth_key, "%s%02x", auth_key, s->ik[i]);
    }
    char *cmd = NULL;
    asprintf(&cmd, "ip netns exec epdg ip xfrm state add src %s dst %s spi 0x%x proto esp auth-trunc 'hmac(md5)' %s 96 enc 'ecb(cipher_null)' ''",
        s->addr_local, s->addr_remote,
        TIPSEC_CTX(s)->spi_ps,
        auth_key);
    fprintf(stderr, "PHH-IPSec: Running %s\n", cmd);
    system(cmd);
    asprintf(&cmd, "ip netns exec epdg ip xfrm policy add src %s dst %s dir out tmpl src %s dst %s spi 0x%x proto esp",
        s->addr_local, s->addr_remote,
        s->addr_local, s->addr_remote,
        TIPSEC_CTX(s)->spi_ps);
    fprintf(stderr, "PHH-IPSec: Running %s\n", cmd);
    system(cmd);
    #if 1
    asprintf(&cmd, "ip netns exec epdg ip xfrm state add src %s dst %s spi 0x%x proto esp auth-trunc 'hmac(md5)' %s 96 enc 'ecb(cipher_null)' ''",
        s->addr_remote, s->addr_local,
        TIPSEC_CTX(s)->spi_us,
        auth_key);
    fprintf(stderr, "PHH-IPSec: Running %s\n", cmd);
    system(cmd);
    asprintf(&cmd, "ip netns exec epdg ip xfrm policy add src %s dst %s dir in tmpl src %s dst %s spi 0x%x proto esp",
        s->addr_remote, s->addr_local,
        s->addr_remote, s->addr_local,
        TIPSEC_CTX(s)->spi_us);
    fprintf(stderr, "PHH-IPSec: Running %s\n", cmd);
    system(cmd);
    #endif
    return tipsec_error_success;
}

static tipsec_error_t _plugin_linux_ipsec_ctx_stop(tipsec_ctx_t* _p_ctx) {
    fprintf(stderr, "PHH-IPSec: Calling stop\n");
    return tipsec_error_success;
}

static const tsk_object_def_t plugin_linux_ipsec_ctx_def_s = {
    sizeof(plugin_linux_ipsec_ctx_t),
    _plugin_linux_ipsec_ctx_ctor,
    _plugin_linux_ipsec_ctx_dtor,
    tsk_null,
};
/* plugin definition*/
static const tipsec_plugin_def_t plugin_linux_ipsec_plugin_def_s = {
    &plugin_linux_ipsec_ctx_def_s,

    tipsec_impl_type_ltools,
    "Linux IPSec",

    _plugin_linux_ipsec_ctx_init,
    _plugin_linux_ipsec_ctx_set_local,
    _plugin_linux_ipsec_ctx_set_remote,
    _plugin_linux_ipsec_ctx_set_keys,
    _plugin_linux_ipsec_ctx_start,
    _plugin_linux_ipsec_ctx_stop,
};
const tipsec_plugin_def_t *plugin_linux_ipsec_plugin_def_t = &plugin_linux_ipsec_plugin_def_s;

void phh_ipsec_init(void) {
    tipsec_plugin_register_static(plugin_linux_ipsec_plugin_def_t);
}
