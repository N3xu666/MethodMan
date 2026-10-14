# CMS

> Part of [01 Web](../README.md) in the [Web Application Testing Cheatsheet](../README.md).

Content management systems and database management panels commonly found on
the web perimeter. CMS platforms are attractive targets because of their
plugin/theme ecosystem: a single unpatched plugin often means pre-auth RCE.
Database panels (Adminer, phpMyAdmin) are included here because they are
often the fastest path from a leaked credential to full DB access.

---

## Files

| File | Type | Description |
|------|------|-------------|
| [Adminer.md](./Adminer.md) | DB management panel | Adminer - single-file PHP DB client, exposed via misconfiguration. |
| [Drupal.md](./Drupal.md) | CMS | Drupal - Drupalgeddon family, module CVEs, `CHANGELOG.txt` fingerprinting. |
| [Joomla.md](./Joomla.md) | CMS | Joomla - component/module CVEs, `administrator/` panel, configuration.php. |
| [Magento.md](./Magento.md) | E-commerce CMS | Magento / Adobe Commerce - admin path obfuscation, payment and API CVEs. |
| [phpMyAdmin.md](./phpMyAdmin.md) | DB management panel | phpMyAdmin - setup script, `pma` paths, known SQL/RCE CVEs. |
| [PrestaShop.md](./PrestaShop.md) | E-commerce CMS | PrestaShop - module CVEs, `admin` panel, database access. |
| [WordPress.md](./WordPress.md) | CMS | WordPress - plugin/theme CVEs, `wp-json`, XML-RPC, wp-config.php. |

---

> See [01 Web README](../README.md) for the full subcategory map.