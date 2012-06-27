imported to github from: https://code.google.com/p/srp-js/

License: [New BSD License](http://www.opensource.org/licenses/bsd-license.php)

Many websites today require some form of authentication to access the site's full functionality. Unfortunately, many of these websites do not use secure authentication protocols.

In some cases, websites will store user passwords in their database. If the database ever becomes compromised, an attacker could authenticate as any user he wanted.

More security savvy websites will store user passwords in their database only after irreversible encryption has been applied. This prevents a leaked copy of the database from compromising user authentication.

But even the more secure of these methods has one major drawback - the user's password is sent across the internet in plain text. Anyone capable of capturing packets, perhaps on a wireless network, is able to see a user's password when the user logs in.

The Secure Remote Password protocol addresses this problem. First presented by T. Wu of Stanford in 1998, SRP has been used in some applications for over a decade. SRP addresses both of the issues previously mentioned: the server does not store information that could be used to login, and the client does not transmit the password in plain text.

This project aims to provide a strong javascript implementation of SRP that will provide some peace of mind when using websites that do not use HTTPS. Due to the nature of HTTP, it is not invulnerable to man-in-the-middle attacks, but it should provide strong security against passive eavesdroppers, which are increasingly common in the age of wireless internet.

To accompany the Javascript implementation of the client, I plan to create server side implementations in Django, PHP, and ASP.NET. Currently, only the Django implementation has begun. 
