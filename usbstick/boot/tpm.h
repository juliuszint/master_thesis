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

int tpm_statuscheck(uint8_t* major, uint8_t* minor);
int tpm_printpcr(uint32_t from_index, uint32_t to_index);
int tpm_random(void* buf, uint32_t buf_size);
int tpm_sealdata(void* data, uint32_t data_size, void* sealed_data, uint32_t* sealed_data_size);
int tpm_unsealdata(void* sealed_data, uint32_t sealed_data_size, void* unsealed_data, uint32_t* unsealed_data_size);
