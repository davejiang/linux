// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/key.h>
#include <keys/asymmetric-type.h>

int x509_get_certificate_length(const u8 *p, unsigned long buflen)
{
	int plen;

	/* Each cert begins with an ASN.1 SEQUENCE tag and must be more
	 * than 256 bytes in size.
	 */
	if (buflen < 4)
		return -EINVAL;

	if (p[0] != 0x30 &&
	    p[1] != 0x82)
		return -EINVAL;

	plen = (p[2] << 8) | p[3];
	plen += 4;
	if (plen > buflen)
		return -EINVAL;

	return plen;
}
EXPORT_SYMBOL_GPL(x509_get_certificate_length);

int x509_load_certificate_list(const u8 cert_list[],
			       const unsigned long list_size,
			       const struct key *keyring)
{
	key_ref_t key;
	const u8 *p, *end;
	int plen;

	p = cert_list;
	end = p + list_size;
	while (p < end) {
		plen = x509_get_certificate_length(p, end - p);
		if (plen < 0)
			goto dodgy_cert;

		key = key_create_or_update(make_key_ref(keyring, 1),
					   "asymmetric",
					   NULL,
					   p,
					   plen,
					   ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
					   KEY_USR_VIEW | KEY_USR_READ),
					   KEY_ALLOC_NOT_IN_QUOTA |
					   KEY_ALLOC_BUILT_IN |
					   KEY_ALLOC_BYPASS_RESTRICTION);
		if (IS_ERR(key)) {
			pr_err("Problem loading in-kernel X.509 certificate (%ld)\n",
			       PTR_ERR(key));
		} else {
			pr_notice("Loaded X.509 cert '%s'\n",
				  key_ref_to_ptr(key)->description);
			key_ref_put(key);
		}
		p += plen;
	}

	return 0;

dodgy_cert:
	pr_err("Problem parsing in-kernel X.509 certificate list\n");
	return 0;
}
EXPORT_SYMBOL_GPL(x509_load_certificate_list);
