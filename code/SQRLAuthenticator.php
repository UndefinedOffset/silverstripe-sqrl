<?php
use Trianglman\Sqrl\SqrlGenerate;
use Trianglman\Sqrl\SqrlRequestHandlerInterface;

class SQRLAuthenticator extends MemberAuthenticator {
    private static $_sqrl=false;
    
    /**
     * Method to authenticate an user
     * @param {array} $RAW_data Raw data to authenticate the user
     * @param {Form} $form Optional: If passed, better error messages can be produced by using {@link Form::sessionMessage()}
     * @return {bool|Member} Returns FALSE if authentication fails, otherwise the member object
     *
     * @see Security::setDefaultAdmin()
     */
    public static function authenticate($RAW_data, Form $form = null) {
        if(!empty($RAW_data['Email']) && !empty($RAW_data['Password'])) {
            return parent::authenticate($RAW_data, $form);
        }else {
            $nonce=SQRLNonce::get()->filter('Nonce', Convert::raw2sql($RAW_data['SQRLNonce']))->first();
            if($nonce->Action==SqrlRequestHandlerInterface::USER_LOGGED_IN) {
                if($nonce->PublicKey() && $nonce->PublicKey()->Member()) {
                    $nonce->PublicKey()->Member()->login();
                    return true;
                }else {
                    //Register
                    $form->sessionMessage('Not Registered', 'bad');
                    return false;
                }
            }else {
                var_dump($nonce->Action, SqrlRequestHandlerInterface::USER_LOGGED_IN);exit;
                $form->sessionMessage('Invalid Sqrl Response', 'bad');
                return false;
            }
        }
    }
    
	/**
	 * Method that creates the login form for this authentication method
	 * @param {Controller} The parent controller, necessary to create the appropriate form action tag
	 * @return {Form} Returns the login form to use with this authentication method
	 */
	public static function get_login_form(Controller $controller) {
		return Object::create("SQRLLoginForm", $controller, "LoginForm");
	}
	
    /**
     * Get the name of the authentication method
     * @return {string} Returns the name of the authentication method.
     */
    public static function get_name() {
        return _t('SQRLAuthenticator.SQRL', 'SQRL');
    }
    
    /**
     * Gets an instance of SqrlGenerate
     * @return {SqrlGenerate} SQRL Generate instance
     */
    public static function getSQRLConfig() {
        $sqrlConfig=new \Trianglman\Sqrl\SqrlConfiguration();
        $sqrlConfig->setQrHeight(SQRLAuthenticator::config()->QRHeight);
        $sqrlConfig->setQrPadding(SQRLAuthenticator::config()->QRPadding);
        $sqrlConfig->setSecure(SQRLAuthenticator::config()->UseSecure);
        $sqrlConfig->setDomain(parse_url(Director::absoluteBaseURL(), PHP_URL_HOST));
        $sqrlConfig->setAuthenticationPath(substr(parse_url(Director::absoluteBaseURL(), PHP_URL_PATH), 1).'SQRLAuthentication/authenticate');
        $sqrlConfig->setAnonAllowed(true);
        $sqrlConfig->setFriendlyName((class_exists('SiteConfig') ? SiteConfig::get()->first()->Title:'SilverStripe'));
        
        $salt=SQRLAuthenticator::config()->NonceSalt;
        if(empty($salt)) {
            user_error('You need to set the salt to be used with SQRL. Use the configuration SQRLAuthenticator->NonceSalt', E_USER_ERROR);
        }
        
        $sqrlConfig->setNonceSalt($salt);
        
        return $sqrlConfig;
    }
    
    /**
     * Gets an instance of SqrlGenerate
     * @return {SqrlGenerate} SQRL Generate instance
     */
    public static function getSQRL() {
        if(self::$_sqrl===false) {
            self::$_sqrl=new \Trianglman\Sqrl\SqrlGenerate(self::getSQRLConfig(), new SilverStripeSQRLStore());
            self::$_sqrl->setRequestorIp($_SERVER['REMOTE_ADDR']);
        }
        
        return self::$_sqrl;
    }
}
?>