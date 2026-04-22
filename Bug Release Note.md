# KNOWN BUGS
While this project does meet nearly all criteria from our requirement book and the Task descriptions, there are two things that are known bugs.

# Access token storage
Described in our requirements, we were going to store tthe access tokens within a database. However, during the implementation process, it became much simplier and more natural for us to store the tokens within the session itself rather than a separate database.

# HTTPS vs HTTP
As required in our requirement book we were going to be using HTTPS for a secure data transfer. However, during implementation it became clear that in order to use HTTPS you need a verified certificate for a web browser to recognize. While ssl_context='adhoc' allows flask to mimic a certificate, it is not verifiable and thus causes fails within the project. As an alternative, we utilized HTTP which is another secure data transfer option, but specifically for local developmental projects and not for production. If this project was ever to be implemented into production, a certificate would need to be invested in and then the necessary changes (primarily changing url calls from http to https) would need to be committed to the project.
