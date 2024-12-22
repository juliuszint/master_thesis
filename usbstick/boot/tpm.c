/*
 * Copyright (c) 2020 Julius Zint <zint.julius@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <lib/libsa/sha1.h>
#include <lib/libsa/hmac_sha1.h>
#include <lib/libsa/stand.h>
#include <machine/biosvar.h>
#include <stand/boot/bootarg.h>

#define TPM_ET_SRK          0x04
#define TPM_ET_XOR          0x00

#define TPM_TAG_RQU_COMMAND         0xc1
#define TPM_TAG_RQU_AUTH1_COMMAND   0xc2
#define TPM_TAG_RQU_AUTH2_COMMAND   0xc3
#define TPM_TAG_RSP_COMMAND         0xc4
#define TPM_TAG_RSP_AUTH1_COMMAND   0xc5
#define TPM_TAG_RSP_AUTH2_COMMAND   0xc6

#define TPM_ORD_GetRandom   0x46
#define TPM_ORD_PCRRead     0x15
#define TPM_ORD_OSAP        0x0b
#define TPM_ORD_OIAP        0x0a
#define TPM_ORD_Seal        0x17
#define TPM_ORD_Unseal      0x18
#define TPM_ORD_ResetLockValue 0x40
#define TPM_ORD_TERMINATE_HANDLE 0x96

#define TPM_PCR_SELECTION_SIZE  3
#define TPM_MAX                 4096
#define TPM_DIGEST_SIZE         20

#define TPM_KH_SRK          0x40000000

#define TPM_LOC_DEFAULT     0x1F
#define TPM_LOC_ZERO        0x01
#define TPM_LOC_ONE         0x02

struct tpm_ipb
{
        uint16_t input_pbl_length;
        uint16_t reserved1;
        uint16_t output_pbl_length;
        uint16_t reserved2;
} __packed;

struct tpm_opb
{
        uint16_t output_length;
        uint16_t reserved1;
} __packed;

struct tpm_digest
{
        unsigned char data[TPM_DIGEST_SIZE];
} __packed;

struct tpm_header {
        uint16_t tag;
        uint32_t length;
        union {
                uint32_t ordinal;
                uint32_t return_code;
        };
} __packed;

struct tpm_request_authorization
{
        uint32_t auth_handle;
        struct tpm_digest nonce_odd;
        uint8_t continue_auth;
        struct tpm_digest pub_auth;
} __packed;

struct tpm_response_authorization
{
        struct tpm_digest nonce_even;
        uint8_t continue_auth;
        struct tpm_digest pub_auth;
} __packed;

struct tpm_pcr_selection
{
        uint16_t length;
        uint8_t bitmap[TPM_PCR_SELECTION_SIZE];
} __packed;

struct tpm_pcr_info
{
    struct tpm_pcr_selection pcr_selection;
    struct tpm_digest digest_at_release;
    struct tpm_digest digest_at_creation;
} __packed;

struct tpm_seal_rqu_payload
{
        uint32_t key_handle;
        struct tpm_digest enc_auth;
        uint32_t pcr_info_size;
        struct tpm_pcr_info pcr_info;
} __packed;

enum TPM_BUFTYPE {
        TPM_BUFTYPE_REQUEST,
        TPM_BUFTYPE_RESPONSE
};

struct tpm_buffer
{
        enum TPM_BUFTYPE type;
        unsigned char* data;
};

struct tpm_entity_type_t
{
        uint8_t encryption;
        uint8_t type;
} __packed;

struct tpm_osap_rqu_payload
{
        uint16_t entitytype;
        uint32_t entityvalue;
        struct tpm_digest nonce_odd_osap;
} __packed;

struct tpm_osap_rsp_payload
{
        uint32_t auth_handle;
        struct tpm_digest nonce_even;
        struct tpm_digest nonce_even_osap;
} __packed;

struct tpm_oiap_rsp_payload
{
        uint32_t auth_handle;
        struct tpm_digest nonce_even;
} __packed;

struct tpm_digest well_known_srk_auth = {};
struct tpm_digest well_known_owner_auth = {};
struct tpm_digest well_known_seal_auth = {};

void
init_tpm_buffer(struct tpm_buffer* buf, enum TPM_BUFTYPE type)
{
        buf->data = alloc(TPM_MAX);
        buf->type = type;
}

void
clear_tpm_buffer(struct tpm_buffer* buf)
{
        memset(buf->data, 0, TPM_MAX);
}

void
destroy_tpm_buffer(struct tpm_buffer* buf)
{
        free(buf->data, TPM_MAX);
}

struct tpm_ipb*
get_ipb(struct tpm_buffer* buf)
{
        return (struct tpm_ipb*)buf->data;
}

struct tpm_opb*
get_opb(struct tpm_buffer* buf)
{
        return (struct tpm_opb*)buf->data;
}

void
init_tpm_pcr_selection(struct tpm_pcr_selection* sel)
{
        sel->length = htons(TPM_PCR_SELECTION_SIZE);
        memset(sel->bitmap, 0, TPM_PCR_SELECTION_SIZE);
}

void
activate_pcr_in_selection(struct tpm_pcr_selection* sel, uint32_t pcr)
{
        sel->bitmap[pcr / 8] |= (0x01 << (pcr % 8));
}

void
deactivate_pcr_in_selection(struct tpm_pcr_selection* sel, uint32_t pcr)
{
        sel->bitmap[pcr / 8] &= ~(0x01 << (pcr % 8));
}

int
is_pcr_selected(struct tpm_pcr_selection* sel, uint32_t pcr)
{
        return (sel->bitmap[pcr / 8] & (0x01 << (pcr % 8))) == 0 ? 0 : 1;
}

int
get_next_set_pcr(struct tpm_pcr_selection* sel, int pcr_offset)
{
        int result = -1;
        uint max_pcr_index = TPM_PCR_SELECTION_SIZE * 8;
        for(int i = pcr_offset + 1; i < max_pcr_index; i++) {
                if(is_pcr_selected(sel, i) == 1) {
                        result = i;
                        break;
                }
        }
        return result;
}

uint32_t
count_set_pcr(struct tpm_pcr_selection* sel)
{
        int result = 0;
        int current_pcr = -1;
        while((current_pcr = get_next_set_pcr(sel, current_pcr)) != -1) {
                result++;
        }
        return result;
}

struct tpm_header*
get_tpm_header(struct tpm_buffer* buf)
{
        size_t offset = 0;
        if(buf->type == TPM_BUFTYPE_REQUEST) {
                offset = sizeof(struct tpm_ipb);
        }
        else {
                offset = sizeof(struct tpm_opb);
        }
        return (struct tpm_header*)(buf->data + offset);
}

void*
get_tpm_payload(struct tpm_buffer* buf)
{
        size_t offset = 0;
        if(buf->type == TPM_BUFTYPE_REQUEST) {
                offset = sizeof(struct tpm_ipb) + sizeof(struct tpm_header);
        }
        else {
                offset = sizeof(struct tpm_opb) + sizeof(struct tpm_header);
        }
        return (void*)(buf->data + offset);
}

int
calculate_auth_digest(
    struct tpm_digest* key,
    struct tpm_digest* param_digest,
    struct tpm_digest* nonce_even,
    struct tpm_digest* nonce_odd,
    uint8_t continue_auth,
    struct tpm_digest* result)
{
        size_t digest_size = sizeof(struct tpm_digest);
        size_t scratch_mem_size = (3 * digest_size) + 1;
        unsigned char* scratch_mem = alloc(scratch_mem_size);
        if(scratch_mem == NULL) {
                return -1;
        }

        memcpy(scratch_mem + (0 * digest_size), param_digest->data, digest_size);
        memcpy(scratch_mem + (1 * digest_size), nonce_even->data, digest_size);
        memcpy(scratch_mem + (2 * digest_size), nonce_odd->data, digest_size);
        memcpy(scratch_mem + (3 * digest_size), &continue_auth, 1);

        hmac_sha1(scratch_mem, scratch_mem_size,
                  key->data, TPM_DIGEST_SIZE,
                  result->data);

        free(scratch_mem, scratch_mem_size);
        return 0;
}

/**
 * calculate_request_auth_digest - calculates the authorization digest
 *                                  for a TPM request
 * @key             The key to use for the hmac computation. for OSAP auth
 *                  sessions this is the shared secret and for OIAP the usage
 *                  auth for the entity
 * @param_digest    This is the digest previously computed from the
 *                  contents of the request. 1H1 refered to by Spec
 * @nonce_even      Even Nonce (see rolling nonces)
 * @auth            the authorization is expected to have its nonce set
 *                  to the odd nonce for the request. the pub_auth field
 *                  will be written to
 *
 * Returns:  0 if the calculation succeeds
 *          -1 otherwise.
 */
int
calculate_request_auth_digest(
    struct tpm_digest* key,
    struct tpm_digest* param_digest,
    struct tpm_digest* nonce_even,
    struct tpm_request_authorization* auth)
{
        return calculate_auth_digest(key, param_digest, nonce_even,
                                     &auth->nonce_odd, auth->continue_auth,
                                     &auth->pub_auth);
}

/**
 * calculate_response_auth_digest - calculates the authorization digest
 *                                  for a TPM response
 * @key             The key to use for the hmac computation. for OSAP auth
 *                  sessions this is the shared secret and for OIAP the usage
 *                  auth for the entity
 * @param_digest    This is the digest previously computed from the
 *                  contents of the response. 1H1 refered to by Spec
 * @nonce_odd       Odd Nonce (see rolling nonces)
 * @auth            the authorization is expected to have its nonce set
 *                  to the even nonce from the TPM.
 *
 * Returns:  0 if the calculation succeeds and the auth->pub_auth matches
 *          -1 otherwise.
 */
int
calculate_and_check_response_auth_digest(
    struct tpm_digest* key,
    struct tpm_digest* param_digest,
    struct tpm_digest* nonce_odd,
    struct tpm_response_authorization* auth)
{
        int rc;
        struct tpm_digest pub_auth = {};
        rc = calculate_auth_digest(key, param_digest, &auth->nonce_even,
                                   nonce_odd, auth->continue_auth,
                                   &pub_auth);
        if(rc != 0) {
                return -1;
        }
        for(int i = 0; i < TPM_DIGEST_SIZE; i++) {
                if(pub_auth.data[i] != auth->pub_auth.data[i]) {
                        printf("Invalid response authorization [%d] %02x -> %02x.\n",
                               i, pub_auth.data[i], auth->pub_auth.data[i]);
                        return -1;
                }
        }
        return 0;
}

struct tpm_digest
calculate_seal_inparam_digest(struct tpm_buffer* buf)
{
        SHA1_CTX sha_ctx = {};
        struct tpm_digest result = {};
        struct tpm_header* header = get_tpm_header(buf);
        struct tpm_seal_rqu_payload* payload = get_tpm_payload(buf);

        size_t payload_info_size = sizeof(struct tpm_seal_rqu_payload);
        uint32_t pcr_info_size = ntohl(payload->pcr_info_size);
        SHA1Init(&sha_ctx);
        SHA1Update(&sha_ctx, (unsigned char*)&header->ordinal, 4);
        SHA1Update(&sha_ctx, payload->enc_auth.data, TPM_DIGEST_SIZE);
        SHA1Update(&sha_ctx, (unsigned char*)&payload->pcr_info_size, 4);
        SHA1Update(&sha_ctx, (unsigned char*)&payload->pcr_info, pcr_info_size);
        uint32_t* in_data_length = (uint32_t*)((uint8_t*)payload + payload_info_size);
        SHA1Update(&sha_ctx, (unsigned char*)in_data_length, 4);
        void* in_data = in_data_length + 1;
        uint32_t data_length = ntohl(*in_data_length);
        SHA1Update(&sha_ctx, in_data, data_length);
        SHA1Final(result.data, &sha_ctx);
        return result;
}

struct tpm_digest
calculate_resetlockvalue_ipd(struct tpm_buffer* buf)
{
        SHA1_CTX sha_ctx = {};
        struct tpm_digest result = {};
        struct tpm_header* header = get_tpm_header(buf);
        SHA1Init(&sha_ctx);
        SHA1Update(&sha_ctx, (unsigned char*)&header->ordinal, 4);
        SHA1Final(result.data, &sha_ctx);
        return result;
}

struct tpm_digest
calculate_unseal_opd(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf)
{
        SHA1_CTX sha_ctx = {};
        struct tpm_digest result = {};
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        uint32_t* secret_size = get_tpm_payload(rsp_buf);
        void* secret_data = secret_size + 1;
        SHA1Init(&sha_ctx);
        SHA1Update(&sha_ctx, (unsigned char*)&response_header->return_code, 4);
        SHA1Update(&sha_ctx, (unsigned char*)&request_header->ordinal, 4);
        SHA1Update(&sha_ctx, (unsigned char*)secret_size, 4);
        SHA1Update(&sha_ctx, (unsigned char*)secret_data, ntohl(*secret_size));
        SHA1Final(result.data, &sha_ctx);
        return result;
}

struct tpm_digest
calculate_seal_opd(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf)
{
        SHA1_CTX sha_ctx = {};
        struct tpm_digest result = {};
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        void* payload = get_tpm_payload(rsp_buf);
        uint32_t payload_size = ntohl(response_header->length)
            - sizeof(struct tpm_header)
            - sizeof(struct tpm_response_authorization);
        SHA1Init(&sha_ctx);
        SHA1Update(&sha_ctx, (unsigned char*)&response_header->return_code, 4);
        SHA1Update(&sha_ctx, (unsigned char*)&request_header->ordinal, 4);
        SHA1Update(&sha_ctx, (unsigned char*)payload, payload_size);
        SHA1Final(result.data, &sha_ctx);
        return result;
}

struct tpm_digest
calculate_resetlockvalue_opd(
    struct tpm_buffer* rqu_buf,
    struct tpm_buffer* rsp_buf)
{
        SHA1_CTX sha_ctx = {};
        struct tpm_digest result = {};
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        SHA1Init(&sha_ctx);
        SHA1Update(&sha_ctx, (unsigned char*)&response_header->return_code, 4);
        SHA1Update(&sha_ctx, (unsigned char*)&request_header->ordinal, 4);
        SHA1Final(result.data, &sha_ctx);
        return result;
}

struct tpm_digest
calculate_unseal_inparam_digest(struct tpm_buffer* buf)
{
        SHA1_CTX sha_ctx = {};
        struct tpm_digest result = {};
        struct tpm_header* header = get_tpm_header(buf);
        uint32_t* key_handle = get_tpm_payload(buf);
        uint32_t data_size = ntohl(header->length)
            - sizeof(struct tpm_header)
            - sizeof(uint32_t)
            - sizeof(struct tpm_request_authorization)
            - sizeof(struct tpm_request_authorization);
        unsigned char* data = (unsigned char*)(key_handle + 1);
        SHA1Init(&sha_ctx);
        SHA1Update(&sha_ctx, (unsigned char*)&header->ordinal, 4);
        SHA1Update(&sha_ctx, data, data_size);
        SHA1Final(result.data, &sha_ctx);
        return result;
}

/**
 * get_tpm_request_auth1 - returns the location of the TPM auth
 *
 * Returns: tpm_request_authorization location in buffer
 *
 * Remarks: the tpm_header needs to be filled out for this to work. the
 *          length in the tpm_header is expected to be in Network byte
 *          order
 */
struct tpm_request_authorization*
get_tpm_request_auth1(struct tpm_buffer* buf)
{
        struct tpm_header* header = get_tpm_header(buf);
        uint32_t request_size = ntohl(header->length);
        uint32_t tag = ntohs(header->tag);
        if(request_size > TPM_MAX) {
            printf("Sanity check for TPM-Packet length failed (rqu_auth_1)\n");
        }
        if(tag != TPM_TAG_RQU_AUTH1_COMMAND && tag != TPM_TAG_RQU_AUTH2_COMMAND) {
            printf("Sanity check for TPM-Packet tag failed (rqu_auth_1)\n");
        }
        uint8_t multiplier = tag == TPM_TAG_RQU_AUTH1_COMMAND ? 1 : 2;
        size_t auth_size = sizeof(struct tpm_request_authorization);
        uint8_t* auth_loc = ((uint8_t*)header) + request_size - (auth_size * multiplier);
        return (struct tpm_request_authorization*)auth_loc;
}

/**
 * get_tpm_request_auth2 - returns the location of the second TPM auth
 *
 * Returns: second tpm_request_authorization location in buffer
 *
 * Remarks: the tpm_header needs to be filled out for this to work. the
 *          length in the tpm_header is expected to be in Network byte
 *          order
 */
struct tpm_request_authorization*
get_tpm_request_auth2(struct tpm_buffer* buf)
{
        struct tpm_header* header = get_tpm_header(buf);
        uint32_t request_size = ntohl(header->length);
        uint32_t tag = ntohs(header->tag);
        if(request_size > TPM_MAX) {
            printf("Sanity check for TPM-Packet length failed (rqu_auth_2)\n");
        }
        if(tag != TPM_TAG_RQU_AUTH2_COMMAND) {
            printf("Sanity check for TPM-Packet tag failed (rqu_auth_2)\n");
        }
        size_t auth_size = sizeof(struct tpm_request_authorization);
        uint8_t* auth_loc = ((uint8_t*)header) + request_size - auth_size;
        return (struct tpm_request_authorization*)auth_loc;
}

/**
 * get_tpm_response_auth1 - returns the location of the TPM auth
 *
 * Returns: tpm_response_authorization location in buffer
 *
 * Remarks: header->tag and header->length are expected to be in network
 *          byte order
 */
struct tpm_response_authorization*
get_tpm_response_auth1(struct tpm_buffer* buf)
{
        struct tpm_header* header = get_tpm_header(buf);
        uint16_t tag = ntohs(header->tag);
        uint32_t request_size = ntohl(header->length);
        if(request_size > TPM_MAX) {
            printf("Sanity check for TPM-Packet length failed (rsp_auth_1)\n");
        }
        if(tag != TPM_TAG_RSP_AUTH1_COMMAND && tag != TPM_TAG_RSP_AUTH2_COMMAND) {
            printf("Sanity check for TPM-Packet tag failed (rsp_auth_1)\n");
        }
        uint8_t multiplier = tag == TPM_TAG_RSP_AUTH1_COMMAND ? 1 : 2;
        size_t auth_size = sizeof(struct tpm_response_authorization);
        uint8_t* auth_loc = ((uint8_t*)header) + request_size - (auth_size * multiplier);
        return (struct tpm_response_authorization*)auth_loc;
}

/**
 * get_tpm_response_auth2 - returns the location of the second TPM auth
 *
 * Returns: tpm_response_authorization location in buffer
 *
 * Remarks: header->tag and header->length are expected to be in network
 *          byte order
 */
struct tpm_response_authorization*
get_tpm_response_auth2(struct tpm_buffer* buf)
{
        struct tpm_header* header = get_tpm_header(buf);
        uint16_t tag = ntohs(header->tag);
        uint32_t request_size = ntohl(header->length);
        if(request_size > TPM_MAX) {
            printf("Sanity check for TPM-Packet length failed (rsp_auth_2)\n");
        }
        if(tag != TPM_TAG_RSP_AUTH2_COMMAND) {
            printf("Sanity check for TPM-Packet tag failed (rsp_auth_2)\n");
        }
        size_t auth_size = sizeof(struct tpm_response_authorization);
        uint8_t* auth_loc = ((uint8_t*)header) + request_size - auth_size;
        return (struct tpm_response_authorization*)auth_loc;
}

/**
 * tpm_statuscheck - is a TCG compliant bios available
 * @major: where to write the TPM major version if available
 * @minor: where to write the TPM minor version if available
 *
 * Return:  0 if TCG compliant bios is available
 *         -1 otherwise
 */
int
tpm_statuscheck(uint8_t* major, uint8_t* minor)
{
        int rc = -1;
	__asm volatile("movl $0xBB00, %%eax\n\t"
	    DOINT(0x1a) "\n\t"
	    :
	    :
	    : "%eax", "%ecx", "%edx", "%ebx", "cc");

	if(BIOS_regs.biosr_ax == 0x00 && BIOS_regs.biosr_bx == 0x41504354) {
            rc = 0;
            *minor = (uint8_t)(BIOS_regs.biosr_cx >> 0);
            *major = (uint8_t)(BIOS_regs.biosr_cx >> 8);
	}
        return rc;
}

int
check_tpm_response(struct tpm_header* header, uint16_t expected_tag, const char* command)
{
        uint16_t tag = ntohs(header->tag);
        uint32_t rc = ntohl(header->return_code);
        if(rc != 0) {
                printf("TCG Error: %08x (%u) in %s\n", rc, rc, command);
                return -1;
        }
        if(tag != expected_tag) {
                printf("Unexpected tag: %08x -> %08x in %s\n",
                       expected_tag, tag, command);
                return -1;
        }
        return 0;
}

/**
 * encrypt_auth - encrypts the supplied authorization data for sealing
 *                data. this prevents the disclosure of the auth_data
 *                to attackers sitting on the LPC bus
 * @auth:           the auth_data unencrypted. the result will be written
 *                  to this parameter.
 * @shared_secret   the shared secret obtained via a osap session
 * @nonce_even      the last even nonce (see rolling nonces)
 *
 * Remarks: the result will be written to @auth
 */
void
encrypt_auth(struct tpm_digest* auth,
             struct tpm_digest* shared_secret,
             struct tpm_digest* nonce_even)
{
        struct tpm_digest xor_pad = {};
        SHA1_CTX digest_ctx;
        SHA1Init(&digest_ctx);
        SHA1Update(&digest_ctx, shared_secret->data, TPM_DIGEST_SIZE);
        SHA1Update(&digest_ctx, nonce_even->data, TPM_DIGEST_SIZE);
        SHA1Final(xor_pad.data, &digest_ctx);
        for(int i = 0; i < TPM_DIGEST_SIZE; i++) {
            auth->data[i] = auth->data[i] ^ xor_pad.data[i];
        }
        return;
}

/**
 * calculate_osap_shared_secret - calculates the shared secret for
 *                                transmitting new usage_auth
 * @nonce_odd_osap:     odd nonce send to TPM via tpm_osap
 * @nonce_even_osap:    even nonce received from TPM via tpm_osap
 * @entity_usage_auth:  usage_auth digest for Entity (e.g. for keyhandle)
 * @result:             digest to write the shared secret to
 *
 * Return:   0 if the calculation succeeds
 *          -1 otherwise
 */
int
calculate_osap_shared_secret(
    struct tpm_digest* nonce_even_osap,
    struct tpm_digest* nonce_odd_osap,
    struct tpm_digest* entity_usage_auth,
    struct tpm_digest* result)
{
        //sharedSecret = HMAC(key.usageAuth, nonceEvenOSAP | nonceOddOSAP)
        size_t digest_size = sizeof(struct tpm_digest);
        size_t scratch_size = digest_size * 2;
        uint8_t* scratch = alloc(scratch_size);
        if(scratch == NULL) {
            return -1;
        }
        memcpy(scratch + (0 * digest_size), nonce_even_osap, digest_size);
        memcpy(scratch + (1 * digest_size), nonce_odd_osap, digest_size);
        hmac_sha1(
            scratch, scratch_size,
            entity_usage_auth->data, digest_size,
            result->data);

        free(scratch, scratch_size);
        return 0;;
}

/**
 * tcg_passthroughtotpm - send command to TPM via BIOS passtrough
 * @request_buffer:     request buffer with the seralized request
 *                      type needs to be: TPM_BUFTYPE_REQUEST
 * @response_buffer:    empty buffer to write the response to
 *                      type needs to be: TPM_BUFTYPE_RESPONSE
 *
 * Return:  0 if the BIOS passtrough result indicates sucess
 *         -1 otherwise
 */
int
tcg_passthroughtotpm(struct tpm_buffer* request_buffer,
                     struct tpm_buffer* response_buffer)
{
        if(request_buffer->type != TPM_BUFTYPE_REQUEST) {
                printf("request_buffer.type != TPM_BUFTYPE_REQUEST");
                return -1;
        }
        if(response_buffer->type != TPM_BUFTYPE_RESPONSE) {
                printf("request_buffer.type != TPM_BUFTYPE_RESPONSE");
                return -1;
        }

        struct tpm_header* tpm_header = get_tpm_header(request_buffer);
        uint32_t request_size = ntohl(tpm_header->length);

        struct tpm_ipb* input_param_block = get_ipb(request_buffer);
        input_param_block->input_pbl_length = request_size + sizeof(struct tpm_ipb);
        input_param_block->output_pbl_length = TPM_MAX;
        void* rqu_buff = request_buffer->data;
        void* rsp_buff = response_buffer->data;

        // do bios interrupt
        BIOS_regs.biosr_es = ((uint32_t)rqu_buff) >> 4; // input  parameter block
        BIOS_regs.biosr_ds = ((uint32_t)rsp_buff) >> 4; // output parameter block
        uint32_t rqu_offset = (uint32_t)rqu_buff & 0xF;
        uint32_t rsp_offset = (uint32_t)rsp_buff & 0xF;
	__asm volatile(
            "movl $0x41504354, %%ebx\n\t"
            "movl $0xBB02, %%eax\n\t"
            "movl $0x00,   %%ecx\n\t"
            "movl $0x00,   %%edx\n\t"
            "movl %0,      %%esi\n\t"
            "movl %1,      %%edi\n\t"
	    DOINT(0x1a) "\n\t"
	    :
	    : "m" (rsp_offset), "m" (rqu_offset)
	    : "%eax", "%ecx", "%edx", "%ebx", "%edi", "%esi", "cc");

        // prepare result
        uint32_t rc = BIOS_regs.biosr_ax;
        if(rc != 0) {
                printf("TCG_PassThroughToTPM error: %08x\n", rc);
                return -1;
        }
        else {
            return 0;
        }
}

/**
 * tpm_getrandom - request random data from a TPM
 * @rqu_buff    memory buffer to prepare request for TPM
 * @rsp_buff    memory buffer to receive response from TPM
 * @buf:        buffer to write random data to
 * @buf_size:   size of bytes to request from TPM
 *
 * Return: 0 if @buf_size random bytes were successfully written to @buf
 *        -1 otherwise
 */
int
tpm_getrandom(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
              void* buf, uint32_t buf_size)
{
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header) + sizeof(uint32_t);
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_GetRandom);

        uint32_t* request_payload = get_tpm_payload(rqu_buf);
        *request_payload = htonl(buf_size);

        int rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }
        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_COMMAND, "tpm_getrandom") != 0) {
                return -1;
        }

        uint32_t* response_payload = get_tpm_payload(rsp_buf);
        void* random_data = (void*)(response_payload + 1);
        uint32_t received_bytes = ntohl(*response_payload);

        if(received_bytes != buf_size) {
                printf("Less random bytes received than requested: %08x -> %08x\n",
                       buf_size, received_bytes);
                return -1;
        }

        memcpy(buf, random_data, buf_size);
        return 0;
}

/**
 * tpm_readpcr - read the PCR value from the TPM
 * @rqu_buff    memory buffer to prepare request for TPM
 * @rsp_buff    memory buffer to receive response from TPM
 * @pcr_index:  the PCR index to read (e.g 8 or 9)
 * @digest:     the digest to write the result to
 *
 * Returns:  0 if the PCR value was successfully written to @digest
 *          -1 otherwise
 */
int
tpm_readpcr(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
            uint32_t pcr_index, struct tpm_digest* digest)
{
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header) + sizeof(uint32_t);
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_PCRRead);

        uint32_t* request_payload = get_tpm_payload(rqu_buf);
        *request_payload = htonl(pcr_index);

        int rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_COMMAND, "tpm_readpcr") != 0) {
            return -1;
        }
        uint8_t* response_payload = get_tpm_payload(rsp_buf);

        for(int i = 0; i < TPM_DIGEST_SIZE; i++) {
                digest->data[i] = response_payload[i];
        }
        return 0;
}

/**
 * tpm_osap - start a Object Independent Authorization Protocol Session
 * @rqu_buff            memory buffer to prepare request for TPM
 * @rsp_buff            memory buffer to receive response from TPM
 * @entity_type:        entity type (e.g. TPM_ET_SRK for SKR)
 * @entity_value:       entity value (e.g. TPM_KH_SRK for SRK)
 * @auth_handle:        auth handle to write the generated value from the TPM
 * @nonce_odd_osap:     nonce supplied by caller
 * @nonce_even:         even nonce to write the generated value from the TPM
 * @nonce_even_osap:    osap nonce to write the generated value from the TPM
 *
 * Return:  0 if the TPM command succeded
 *         -1 otherwise
 */
int
tpm_osap(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
         uint16_t entity_type,
         uint32_t entity_value,
         uint32_t* auth_handle,
         struct tpm_digest* nonce_odd_osap,
         struct tpm_digest* nonce_even,
         struct tpm_digest* nonce_even_osap)
{
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header)+ sizeof(struct tpm_osap_rqu_payload);
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_OSAP);

        struct tpm_osap_rqu_payload* request_payload = get_tpm_payload(rqu_buf);
        request_payload->entitytype = htons(entity_type);
        request_payload->entityvalue = htonl(entity_value);
        request_payload->nonce_odd_osap = *nonce_odd_osap;

        int rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_COMMAND, "tpm_osap") != 0) {
                return -1;
        }
        struct tpm_osap_rsp_payload* response_payload = get_tpm_payload(rsp_buf);
        response_payload->auth_handle = ntohl(response_payload->auth_handle);
        *auth_handle = response_payload->auth_handle;
        *nonce_even = response_payload->nonce_even;
        *nonce_even_osap = response_payload->nonce_even_osap;
        return 0;
}

/**
 * tpm_oiap - start a Object Independent Authorization Protocol Session
 * @rqu_buff            memory buffer to prepare request for TPM
 * @rsp_buff            memory buffer to receive response from TPM
 * @auth_handle:        auth handle to write the generated value from the TPM
 * @nonce_even:         even nonce to write the generated value from the TPM
 *
 * Returns:  0 if the TPM command succeded
 *          -1 otherwise
 */
int
tpm_oiap(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
         uint32_t* auth_handle, struct tpm_digest* nonce_even)
{
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header);
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_OIAP);

        int rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_COMMAND, "tpm_oiap") != 0) {
                return -1;
        }
        uint32_t length = ntohl(response_header->length);
        if(length != 34) {
            printf("Less bytes received than expected: %u -> %u\n", 34, length);
            return -1;
        }
        struct tpm_osap_rsp_payload* response_payload = get_tpm_payload(rsp_buf);
        response_payload->auth_handle = ntohl(response_payload->auth_handle);
        *auth_handle = response_payload->auth_handle;
        *nonce_even = response_payload->nonce_even;
        return 0;
}

/**
 * tpm_terminate_handle - terminates a session handle
 * @rqu_buff            memory buffer to prepare request for TPM
 * @rsp_buff            memory buffer to receive response from TPM
 * @auth_handle         the auth_handle (e.g. the result of tpm_osap)
 *
 * Returns:  0 if the TPM command succeded
 *          -1 otherwise
 */
int
tpm_terminate_handle(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
                     uint32_t auth_handle)
{
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header)+ sizeof(uint32_t);
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_TERMINATE_HANDLE);

        uint32_t* request_payload = get_tpm_payload(rqu_buf);
        *request_payload = htonl(auth_handle);

        int rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_COMMAND, "tpm_terminate_handle") != 0) {
                return -1;
        }
        return 0;
}

/**
 * tpm_seal - seals the supplied data via the TPM and returns the encrypted
 *            blob
 * @rqu_buff    memory buffer to prepare request for TPM
 * @rsp_buff    memory buffer to receive response from TPM
 * @blob        buffer containing the data to seal
 * @blob_size   length of the data to seal
 * @auth_handle the osap auth_handle previously obtained via tpm_osap
 * @pcrs        the PCRs to seal the data to
 * @enc_auth    the encrypted usage_auth needed to unseal the blob
 * @nonce_even  the last nonce even returned from a previous TPM command
 * @nonce_odd   the odd nonce to use for this request
 * @usage_auth  usage auth data for the key used with auth_handle
 * @sealed_data pointer to set to the sealed data. this points to a memory
 *              location inside the rsp_buf. a subsequent request could
 *              possible overwrite this data.
 * @sealed_size length of the sealed size
 *
 * Returns:  0 if the TPM command successeds
 *          -1 otherwise
 */
int
tpm_seal(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
         void* blob, uint32_t blob_size, uint32_t auth_handle,
         struct tpm_pcr_info* pcr_info, struct tpm_digest* enc_auth,
         struct tpm_digest* nonce_even, struct tpm_digest* nonce_odd,
         struct tpm_digest* shared_secret, void** sealed_data,
         uint32_t* sealed_size)
{
        int rc;
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        size_t payload_info_size = sizeof(struct tpm_seal_rqu_payload);
        uint32_t request_size = sizeof(struct tpm_header)
            + payload_info_size
            + sizeof(uint32_t)
            + blob_size
            + sizeof(struct tpm_request_authorization);

        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_AUTH1_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_Seal);

        struct tpm_seal_rqu_payload* rqu_payload = get_tpm_payload(rqu_buf);
        rqu_payload->key_handle = htonl(TPM_KH_SRK);
        rqu_payload->enc_auth = *enc_auth;
        rqu_payload->pcr_info_size = htonl(sizeof(struct tpm_pcr_info));
        rqu_payload->pcr_info = *pcr_info;
        uint32_t* in_data_length = (uint32_t*)((uint8_t*)rqu_payload + payload_info_size);
        void* in_data = in_data_length + 1;
        *in_data_length = htonl(blob_size);
        memcpy(in_data, blob, blob_size);

        struct tpm_digest ipd = calculate_seal_inparam_digest(rqu_buf);
        struct tpm_request_authorization* rqu_auth = get_tpm_request_auth1(rqu_buf);
        rqu_auth->auth_handle = htonl(auth_handle);
        rqu_auth->nonce_odd = *nonce_odd;
        rqu_auth->continue_auth = 0; // ignored in commands that introduce new auth_data
        rc = calculate_request_auth_digest(
            shared_secret, &ipd, nonce_even, rqu_auth);
        if(rc != 0) {
            return -1;
        }

        rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_AUTH1_COMMAND, "tpm_seal") != 0) {
                return -1;
        }
        struct tpm_response_authorization* rsp_auth = get_tpm_response_auth1(rsp_buf);
        struct tpm_digest opd = calculate_seal_opd(rqu_buf, rsp_buf);
        rc = calculate_and_check_response_auth_digest(
            shared_secret, &opd, nonce_odd, rsp_auth);

        void* payload = get_tpm_payload(rsp_buf);
        uint32_t payload_size = ntohl(response_header->length)
            - sizeof(struct tpm_header)
            - sizeof(struct tpm_response_authorization);
        *sealed_size = payload_size;
        *sealed_data = payload;

        return 0;
}

/**
 * tpm_unseal - seals the supplied data via the TPM and returns the encrypted
 *            blob
 * @rqu_buff    memory buffer to prepare request for TPM
 * @rsp_buff    memory buffer to receive response from TPM
 * @blob        buffer containing the sealed data
 * @blob_size   length of the sealed data
 *
 * Returns:  0 if the TPM command successeds
 *          -1 otherwise
 */
int
tpm_unseal(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
           void* blob, uint32_t blob_size,
           uint32_t key_auth_handle, uint32_t data_auth_handle,
           struct tpm_digest* nonce_even, struct tpm_digest* nonce_odd,
           struct tpm_digest* data_nonce_even, struct tpm_digest* data_nonce_odd,
           struct tpm_digest* key_usage_auth, struct tpm_digest* entity_usage_auth,
           void** unsealed_data, uint32_t* unsealed_size)
{
        int rc;
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header)
            + sizeof(uint32_t)                          // parentHandle
            + blob_size                                 // inData
            + sizeof(struct tpm_request_authorization)  // auth_1
            + sizeof(struct tpm_request_authorization); // auth_2

        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_AUTH2_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_Unseal);

        uint32_t* parent_key = get_tpm_payload(rqu_buf);
        uint8_t* in_data = (uint8_t*)(parent_key + 1);
        *parent_key = htonl(TPM_KH_SRK);
        memcpy(in_data, blob, blob_size);

        struct tpm_digest ipd = calculate_unseal_inparam_digest(rqu_buf);
        struct tpm_request_authorization* rqu_auth1 = get_tpm_request_auth1(rqu_buf);
        rqu_auth1->auth_handle = htonl(key_auth_handle);
        rqu_auth1->nonce_odd = *nonce_odd;
        rqu_auth1->continue_auth = 0;
        rc = calculate_request_auth_digest(
            key_usage_auth, &ipd, nonce_even, rqu_auth1);
        if(rc != 0) {
            return -1;
        }

        struct tpm_request_authorization* rqu_auth2 = get_tpm_request_auth2(rqu_buf);
        rqu_auth2->auth_handle = htonl(data_auth_handle);
        rqu_auth2->nonce_odd = *data_nonce_odd;
        rqu_auth2->continue_auth = 0;
        rc = calculate_request_auth_digest(
            entity_usage_auth, &ipd, data_nonce_even, rqu_auth2);
        if(rc != 0) {
            return -1;
        }

        rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_AUTH2_COMMAND, "tpm_unseal") != 0) {
                return -1;
        }
        struct tpm_digest opd = calculate_unseal_opd(rqu_buf, rsp_buf);
        struct tpm_response_authorization* rsp_auth1 = get_tpm_response_auth1(rsp_buf);
        rc = calculate_and_check_response_auth_digest(
            key_usage_auth, &opd, nonce_odd, rsp_auth1);
        if(rc != 0) {
            return -1;
        }
        struct tpm_response_authorization* rsp_auth2 = get_tpm_response_auth2(rsp_buf);
        rc = calculate_and_check_response_auth_digest(
            entity_usage_auth, &opd, data_nonce_odd, rsp_auth2);
        if(rc != 0) {
            return -1;
        }

        uint32_t* secret_size = get_tpm_payload(rsp_buf);
        void* secret_data = secret_size + 1;
        *unsealed_size = ntohl(*secret_size);
        *unsealed_data = secret_data;

        return 0;
}

/**
 * tpm_resetlockvalue - resets tpm dictionary attack mitigations
 * @rqu_buff        memory buffer to prepare request for TPM
 * @rsp_buff        memory buffer to receive response from TPM
 * @nonce_even      even nonce (see rolling nonces)
 * @nonce_odd       odd nonce (see rolling nonces)
 * @owner_secret    tpm owner secret (see tpm_takeownership)
 * @auth_handle     auth handle previously obtained via tpm_oiap
 *
 * Returns:  0 if the attack mitigations were successfully reset
 *          -1 otherwise
 */
int
tpm_resetlockvalue(struct tpm_buffer* rqu_buf, struct tpm_buffer* rsp_buf,
                   struct tpm_digest* nonce_even, struct tpm_digest* nonce_odd,
                   struct tpm_digest* owner_secret, uint32_t auth_handle)
{
        int rc;
        clear_tpm_buffer(rqu_buf);
        clear_tpm_buffer(rsp_buf);

        uint32_t request_size = sizeof(struct tpm_header)
            + sizeof(struct tpm_request_authorization);
        struct tpm_header* request_header = get_tpm_header(rqu_buf);
        request_header->tag = htons(TPM_TAG_RQU_AUTH1_COMMAND);
        request_header->length = htonl(request_size);
        request_header->ordinal = htonl(TPM_ORD_ResetLockValue);

        struct tpm_digest ipd = calculate_resetlockvalue_ipd(rqu_buf);

        struct tpm_request_authorization* rqu_auth = get_tpm_request_auth1(rqu_buf);
        rqu_auth->auth_handle = htonl(auth_handle);
        rqu_auth->nonce_odd = *nonce_odd;
        rqu_auth->continue_auth = 0;
        rc = calculate_request_auth_digest(
            owner_secret, &ipd, nonce_even, rqu_auth);
        if(rc != 0) {
            return -1;
        }

        rc = tcg_passthroughtotpm(rqu_buf, rsp_buf);
        if(rc != 0) {
                return -1;
        }

        struct tpm_header* response_header = get_tpm_header(rsp_buf);
        if(check_tpm_response(response_header, TPM_TAG_RSP_AUTH1_COMMAND, "tpm_unseal") != 0) {
                return -1;
        }

        struct tpm_response_authorization* rsp_auth = get_tpm_response_auth1(rsp_buf);
        struct tpm_digest opd = calculate_resetlockvalue_opd(rqu_buf, rsp_buf);
        rc = calculate_and_check_response_auth_digest(
            owner_secret, &opd, nonce_odd, rsp_auth);
        if(rc != 0) {
                return -1;
        }

        return 0;
}

int
calculate_pcr_digest(struct tpm_pcr_selection* sel,
                     struct tpm_digest* pcr_values,
                     int pcr_values_length,
                     struct tpm_digest* result)
{
        size_t pcr_selection_size = sizeof(struct tpm_pcr_selection);
        uint32_t selected_pcr_count = count_set_pcr(sel);

        SHA1_CTX digest_ctx;
        SHA1Init(&digest_ctx);
        SHA1Update(&digest_ctx, (unsigned char*)sel, pcr_selection_size);
        uint32_t total_digest_bytes = htonl(selected_pcr_count * SHA1_DIGEST_LENGTH);
        SHA1Update(&digest_ctx, (unsigned char*)&total_digest_bytes, 4);
        int current_pcr = get_next_set_pcr(sel, -1);
        while(current_pcr != -1) {
                if(current_pcr >= pcr_values_length) {
                        printf("out of range in supplied pcr_values");
                        return -1;
                }
                SHA1Update(&digest_ctx, pcr_values[current_pcr].data, SHA1_DIGEST_LENGTH);
                current_pcr = get_next_set_pcr(sel, current_pcr);
        }
        SHA1Final((unsigned char*)result->data, &digest_ctx);
        return 0;
}

/**
 *                          Application Layer
 *
 *  Funktions in this layer compose one or more of the Command Layer funktions
 *  to provide a higher level functionality like sealing or unsealing of data
 *
 *
 */

void cpu_getrandom(void* buf, uint32_t size)
{
#ifdef MDRANDOM
        mdrandom(buf, size);
#endif
#ifdef FWRANDOM
        fwrandom(buf, size);
#endif
}


/**
 * tpm_print_pcr_registers - prints the content of multiple pcr registers to console
 * @from_index      0 based index for the first pcr to print
 * @to_index        0 based index for the last pcr to print
 *
 * Returns:  0 if successfull
 *          -1 otherwise
 */
int
tpm_printpcr(uint32_t from_index, uint32_t to_index)
{
        int rc = 0;
        struct tpm_buffer rqu_buf;
        struct tpm_buffer rsp_buf;
        init_tpm_buffer(&rqu_buf, TPM_BUFTYPE_REQUEST);
        init_tpm_buffer(&rsp_buf, TPM_BUFTYPE_RESPONSE);

        for(int i = from_index; i < to_index; i++) {
                struct tpm_digest digest;
                if(tpm_readpcr(&rqu_buf, &rsp_buf, i, &digest) == 0) {
                        printf("PCR-%02d:", i);
                        for(int i = 0; i < 20; i++) {
                            printf(" %02x", digest.data[i]);
                        }
                        printf("\n");
                }
                else {
                        rc = -1;
                        break;
                }
        }

        destroy_tpm_buffer(&rqu_buf);
        destroy_tpm_buffer(&rsp_buf);
        return rc;
}

/**
 * tpm_getrandom - gets random data from the tpm chip
 * @buf         buffer to write random data to
 * @buf_size    amount of random bytes to get
 *
 * Returns:  0 if successfull -> buf contains random bytes from tpm
 *          -1 otherwise      -> buf content undefined
 *
 */
int tpm_random(void* buf, uint32_t buf_size)
{
        struct tpm_buffer rqu_buf;
        struct tpm_buffer rsp_buf;
        init_tpm_buffer(&rqu_buf, TPM_BUFTYPE_REQUEST);
        init_tpm_buffer(&rsp_buf, TPM_BUFTYPE_RESPONSE);
        uint32_t rv = tpm_getrandom(&rqu_buf, &rsp_buf, buf, buf_size);
        destroy_tpm_buffer(&rqu_buf);
        destroy_tpm_buffer(&rsp_buf);
        return rv;
}

/**
 * tpm_sealdata - seals data to pcr 4, 8, 9
 * @data                the buffer containing the data to seal
 * @data_size           the size of the data to be sealed
 * @sealed_data         the buffer to write the sealed data to
 * @sealed_data_size    the size of @sealed_data
 *
 * Returns:  0 if successfull -> sealed_data contains the sealed data and the
 *                               sealed_data_size contains the size
 *          -1 otherwise      -> sealed_data unchanged
 *                            -> sealed_data_size unchanged
 */
int
tpm_sealdata(
    void* data,
    uint32_t data_size,
    void* sealed_data,
    uint32_t* sealed_data_size)
{
        int rc;
        struct tpm_buffer rqu_buf;
        struct tpm_buffer rsp_buf;
        init_tpm_buffer(&rqu_buf, TPM_BUFTYPE_REQUEST);
        init_tpm_buffer(&rsp_buf, TPM_BUFTYPE_RESPONSE);

        struct tpm_digest current_pcrs[10];
        for(uint32_t i = 0; i < 10; i++) {
            tpm_readpcr(&rqu_buf, &rsp_buf, i, &current_pcrs[i]);
        }

        struct tpm_pcr_info pcr_info = {};
        init_tpm_pcr_selection(&pcr_info.pcr_selection);
        activate_pcr_in_selection(&pcr_info.pcr_selection, 4); // mbr
        activate_pcr_in_selection(&pcr_info.pcr_selection, 8); // biosboot
        activate_pcr_in_selection(&pcr_info.pcr_selection, 9); // boot
        calculate_pcr_digest(&pcr_info.pcr_selection, current_pcrs,
                             10, &pcr_info.digest_at_release);
        pcr_info.digest_at_creation = pcr_info.digest_at_release;

        struct tpm_digest nonce_odd_osap = {};
        struct tpm_digest nonce_even_osap = {};
        struct tpm_digest nonce_even = {};
        cpu_getrandom(nonce_odd_osap.data, TPM_DIGEST_SIZE);

        uint32_t auth_handle = 0;
        rc = tpm_osap(&rqu_buf, &rsp_buf, TPM_ET_SRK,
                      TPM_KH_SRK, &auth_handle, &nonce_odd_osap,
                      &nonce_even, &nonce_even_osap);
        if(rc != 0) {
            goto out_free;
        }

        struct tpm_digest shared_secret = {};
        rc = calculate_osap_shared_secret(
            &nonce_even_osap, &nonce_odd_osap,
            &well_known_srk_auth, &shared_secret);
        if(rc != 0) {
            goto out_osap;
        }

        struct tpm_digest enc_auth = {};
        encrypt_auth(&enc_auth, &shared_secret, &nonce_even);
        struct tpm_digest nonce_odd = {};
        cpu_getrandom(nonce_odd.data, TPM_DIGEST_SIZE);

        uint32_t local_sealed_size = 0;
        void* local_sealed_data = NULL;

        rc = tpm_seal(&rqu_buf, &rsp_buf, data, data_size, auth_handle,
                      &pcr_info, &enc_auth, &nonce_even, &nonce_odd,
                      &shared_secret, &local_sealed_data, &local_sealed_size);

        if(rc == 0) {
            if(local_sealed_size > *sealed_data_size) {
                printf("sealed_data buffer to smaller than %d bytes\n", local_sealed_size);
            }
            else {
                *sealed_data_size = local_sealed_size;
                memcpy(sealed_data, local_sealed_data, *sealed_data_size);
            }
            goto out_free;
        }

out_osap:
        rc = tpm_terminate_handle(&rqu_buf, &rsp_buf, auth_handle);
out_free:
        destroy_tpm_buffer(&rqu_buf);
        destroy_tpm_buffer(&rsp_buf);

        return rc;
}

/**
 * tpm_unsealdata - unseals data
 * @sealed_data         the buffer containing the previously sealed data
 * @sealed_data_size    size of the sealed data
 * @unsealed_data       buffer to hold the unsealed data
 * @unsealed_data_size  size of the @unsealed_data buffer
 *
 * Returns:  0 if successfull -> @unsealed_data contains the unsealed data and
 *                               the @unsealed_data_size contains the size of it
 *          -1 otherwise      -> @unsealed_data unchanged
 *                            -> @unsealed_data_size unchanged
 */
int
tpm_unsealdata(
    void* sealed_data,
    uint32_t sealed_data_size,
    void* unsealed_data,
    uint32_t* unsealed_data_size)
{
        int rc;

        struct tpm_buffer rqu_buf;
        struct tpm_buffer rsp_buf;
        init_tpm_buffer(&rqu_buf, TPM_BUFTYPE_REQUEST);
        init_tpm_buffer(&rsp_buf, TPM_BUFTYPE_RESPONSE);

        uint32_t key_auth_handle = 0;
        uint32_t data_auth_handle = 0;

        struct tpm_digest nonce_odd_osap = {};
        struct tpm_digest nonce_even_osap = {};
        struct tpm_digest nonce_even = {};
        struct tpm_digest data_nonce_even = {};
        cpu_getrandom(nonce_odd_osap.data, TPM_DIGEST_SIZE);

        // osap session for SRK
        rc = tpm_osap(&rqu_buf, &rsp_buf, TPM_ET_SRK,
                      TPM_KH_SRK, &key_auth_handle, &nonce_odd_osap,
                      &nonce_even, &nonce_even_osap);
        if(rc != 0) {
            goto out;
        }

        // oiap session for sealed data
        rc = tpm_oiap(&rqu_buf, &rsp_buf, &data_auth_handle, &data_nonce_even);
        if(rc != 0) {
            goto out;
        }

        // generate odd nonce for unseal command
        struct tpm_digest unseal_nonce_odd = {};
        struct tpm_digest data_nonce_odd = {};
        cpu_getrandom(data_nonce_odd.data, TPM_DIGEST_SIZE);
        cpu_getrandom(unseal_nonce_odd.data, TPM_DIGEST_SIZE);

        struct tpm_digest shared_secret = {};
        rc = calculate_osap_shared_secret(
            &nonce_even_osap, &nonce_odd_osap,
            &well_known_srk_auth, &shared_secret);
        if(rc != 0) {
            goto out;
        }

        uint32_t local_unsealed_size = 0;
        void* local_unsealed_data = NULL;
        rc = tpm_unseal(&rqu_buf, &rsp_buf, sealed_data, sealed_data_size,
                        key_auth_handle, data_auth_handle,
                        &nonce_even, &unseal_nonce_odd,
                        &data_nonce_even, &data_nonce_odd,
                        &shared_secret, &well_known_seal_auth,
                        &local_unsealed_data, &local_unsealed_size);
        if(rc == 0) {
            if(*unsealed_data_size < local_unsealed_size) {
                printf("unsealed_data buffer to small to hold %d byte\n", local_unsealed_size);
            }
            else {
                *unsealed_data_size = local_unsealed_size;
                memcpy(unsealed_data, local_unsealed_data, local_unsealed_size);
            }
            key_auth_handle = 0;
            data_auth_handle = 0;
        }
out:
        if(data_auth_handle != 0) {
            rc = tpm_terminate_handle(&rqu_buf, &rsp_buf, data_auth_handle);
        }
        if(key_auth_handle != 0) {
            rc = tpm_terminate_handle(&rqu_buf, &rsp_buf, key_auth_handle);
        }
        destroy_tpm_buffer(&rqu_buf);
        destroy_tpm_buffer(&rsp_buf);
        return rc;
}
