<?php
define('SQRLAUTH_BASE', basename(dirname(__FILE__)));

Authenticator::register_authenticator('SQRLAuthenticator');
?>