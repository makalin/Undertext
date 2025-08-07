#include <vlc_common.h>
#include <vlc_plugin.h>
#include <vlc_filter.h>
#include <vlc_block.h>
#include <vlc_es_out.h>
#include <vlc_es_out_id.h>
#include <vlc_subpicture.h>
#include <vlc_text_style.h>
#include <vlc_http.h>
#include <vlc_network.h>
#include <vlc_url.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <json-c/json.h>

#define UNDERtext_FILTER_TEXT N_("Undertext subtitle filter")
#define UNDERtext_FILTER_LONGTEXT N_("Decrypts and displays Undertext subtitles from VANC data")

typedef struct {
    filter_t *p_filter;
    es_out_id_t *p_es;
    char *p_server_url;
    char *p_session_token;
    char *p_stream_id;
    unsigned char *p_decryption_key;
    unsigned char *p_iv;
    size_t key_len;
    size_t iv_len;
    bool b_authenticated;
    vlc_mutex_t lock;
} filter_sys_t;

static int Create(vlc_object_t *);
static void Destroy(vlc_object_t *);
static subpicture_t *Filter(filter_t *, mtime_t);
static int RequestKey(filter_sys_t *);

vlc_module_begin()
    set_shortname("undertext")
    set_description(UNDERtext_FILTER_TEXT)
    set_capability("sub source", 0)
    set_category(CAT_VIDEO)
    set_subcategory(SUBCAT_VIDEO_SUBPIC)
    set_callbacks(Create, Destroy)
vlc_module_end()

static int Create(vlc_object_t *p_this)
{
    filter_t *p_filter = (filter_t *)p_this;
    filter_sys_t *p_sys = malloc(sizeof(*p_sys));
    
    if (!p_sys)
        return VLC_ENOMEM;
    
    p_sys->p_filter = p_filter;
    p_sys->p_es = NULL;
    p_sys->p_server_url = NULL;
    p_sys->p_session_token = NULL;
    p_sys->p_stream_id = NULL;
    p_sys->p_decryption_key = NULL;
    p_sys->p_iv = NULL;
    p_sys->key_len = 0;
    p_sys->iv_len = 0;
    p_sys->b_authenticated = false;
    
    vlc_mutex_init(&p_sys->lock);
    
    // Get configuration
    p_sys->p_server_url = var_GetString(p_filter, "undertext-server");
    p_sys->p_session_token = var_GetString(p_filter, "undertext-token");
    p_sys->p_stream_id = var_GetString(p_filter, "undertext-stream");
    
    if (!p_sys->p_server_url || !p_sys->p_session_token || !p_sys->p_stream_id) {
        msg_Err(p_filter, "Undertext configuration missing");
        free(p_sys);
        return VLC_EGENERIC;
    }
    
    // Request decryption key
    if (RequestKey(p_sys) != VLC_SUCCESS) {
        msg_Err(p_filter, "Failed to obtain decryption key");
        free(p_sys);
        return VLC_EGENERIC;
    }
    
    p_filter->p_sys = p_sys;
    p_filter->pf_sub_source = Filter;
    
    return VLC_SUCCESS;
}

static void Destroy(vlc_object_t *p_this)
{
    filter_t *p_filter = (filter_t *)p_this;
    filter_sys_t *p_sys = p_filter->p_sys;
    
    if (p_sys) {
        free(p_sys->p_server_url);
        free(p_sys->p_session_token);
        free(p_sys->p_stream_id);
        free(p_sys->p_decryption_key);
        free(p_sys->p_iv);
        vlc_mutex_destroy(&p_sys->lock);
        free(p_sys);
    }
}

static int RequestKey(filter_sys_t *p_sys)
{
    vlc_http_cookie_jar_t *p_jar = vlc_http_cookies_new();
    if (!p_jar)
        return VLC_ENOMEM;
    
    // Build request URL
    char *psz_url;
    if (asprintf(&psz_url, "%s/api/v1/keys/request", p_sys->p_server_url) < 0) {
        vlc_http_cookies_destroy(p_jar);
        return VLC_ENOMEM;
    }
    
    // Prepare request data
    char *psz_data;
    if (asprintf(&psz_data, "{\"stream_id\":\"%s\",\"session_token\":\"Bearer %s\"}",
                 p_sys->p_stream_id, p_sys->p_session_token) < 0) {
        free(psz_url);
        vlc_http_cookies_destroy(p_jar);
        return VLC_ENOMEM;
    }
    
    // Send HTTP request
    vlc_http_res_t *p_res = vlc_http_request(psz_url, "POST", p_jar, NULL, psz_data, strlen(psz_data));
    
    free(psz_data);
    free(psz_url);
    
    if (!p_res) {
        vlc_http_cookies_destroy(p_jar);
        return VLC_EGENERIC;
    }
    
    // Parse response
    if (vlc_http_res_get_status(p_res) != 200) {
        vlc_http_res_release(p_res);
        vlc_http_cookies_destroy(p_jar);
        return VLC_EGENERIC;
    }
    
    block_t *p_block = vlc_http_res_read(p_res);
    vlc_http_res_release(p_res);
    vlc_http_cookies_destroy(p_jar);
    
    if (!p_block)
        return VLC_EGENERIC;
    
    // Parse JSON response
    json_object *p_json = json_tokener_parse((char *)p_block->p_buffer);
    block_Release(p_block);
    
    if (!p_json)
        return VLC_EGENERIC;
    
    // Extract key data
    json_object *p_key_data, *p_iv, *p_expires;
    if (json_object_object_get_ex(p_json, "key_data", &p_key_data) &&
        json_object_object_get_ex(p_json, "iv", &p_iv)) {
        
        const char *psz_key = json_object_get_string(p_key_data);
        const char *psz_iv = json_object_get_string(p_iv);
        
        // Decode base64 key and IV
        size_t key_len, iv_len;
        unsigned char *p_key = vlc_b64_decode(psz_key, &key_len);
        unsigned char *p_decoded_iv = vlc_b64_decode(psz_iv, &iv_len);
        
        if (p_key && p_decoded_iv) {
            p_sys->p_decryption_key = p_key;
            p_sys->p_iv = p_decoded_iv;
            p_sys->key_len = key_len;
            p_sys->iv_len = iv_len;
            p_sys->b_authenticated = true;
            
            json_object_put(p_json);
            return VLC_SUCCESS;
        }
        
        free(p_key);
        free(p_decoded_iv);
    }
    
    json_object_put(p_json);
    return VLC_EGENERIC;
}

static subpicture_t *Filter(filter_t *p_filter, mtime_t date)
{
    filter_sys_t *p_sys = p_filter->p_sys;
    
    vlc_mutex_lock(&p_sys->lock);
    
    if (!p_sys->b_authenticated) {
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    // Get subtitle data from VANC
    block_t *p_block = vlc_subpicture_NewBuffer(NULL, 0);
    if (!p_block) {
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    // Decrypt subtitle data
    EVP_CIPHER_CTX *p_ctx = EVP_CIPHER_CTX_new();
    if (!p_ctx) {
        block_Release(p_block);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    if (EVP_DecryptInit_ex(p_ctx, EVP_aes_256_gcm(), NULL, 
                          p_sys->p_decryption_key, p_sys->p_iv) != 1) {
        EVP_CIPHER_CTX_free(p_ctx);
        block_Release(p_block);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    int len;
    unsigned char *p_decrypted = malloc(p_block->i_buffer);
    if (!p_decrypted) {
        EVP_CIPHER_CTX_free(p_ctx);
        block_Release(p_block);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    if (EVP_DecryptUpdate(p_ctx, p_decrypted, &len, 
                         p_block->p_buffer, p_block->i_buffer) != 1) {
        free(p_decrypted);
        EVP_CIPHER_CTX_free(p_ctx);
        block_Release(p_block);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(p_ctx, p_decrypted + len, &final_len) != 1) {
        free(p_decrypted);
        EVP_CIPHER_CTX_free(p_ctx);
        block_Release(p_block);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    EVP_CIPHER_CTX_free(p_ctx);
    block_Release(p_block);
    
    // Create subtitle
    subpicture_t *p_subpic = subpicture_New(NULL);
    if (!p_subpic) {
        free(p_decrypted);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    p_subpic->i_start = date;
    p_subpic->i_stop = date + 3000000; // 3 seconds
    p_subpic->b_ephemer = true;
    p_subpic->b_absolute = false;
    
    // Create text region
    subpicture_region_t *p_region = subpicture_region_New(NULL);
    if (!p_region) {
        subpicture_Delete(p_subpic);
        free(p_decrypted);
        vlc_mutex_unlock(&p_sys->lock);
        return NULL;
    }
    
    p_region->p_text = text_segment_New((char *)p_decrypted);
    p_region->i_align = SUBPICTURE_ALIGN_BOTTOM;
    p_region->i_x = 0;
    p_region->i_y = 0;
    
    p_subpic->p_region = p_region;
    
    free(p_decrypted);
    vlc_mutex_unlock(&p_sys->lock);
    
    return p_subpic;
} 