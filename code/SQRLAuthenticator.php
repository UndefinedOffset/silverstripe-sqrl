<?php
use Trianglman\Sqrl\SqrlGenerate;
use Trianglman\Sqrl\SqrlRequestHandlerInterface;
use Trianglman\Sqrl\SqrlValidate;

class SQRLAuthenticator extends MemberAuthenticator {
    private static $UseSecure=true;
    private static $KeyDomain=null;
    private static $NonceSalt=null;
    private static $NonceMaxAge=60; //5;
    private static $QRHeight=150;
    private static $QRPadding=10;
    
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
            $nonce=SQRLNonce::get()->filter('Nonce', Convert::raw2sql(SilverStripeSQRLStore::create()->getSessionNonce()))->first();
            if($nonce->Verified==true) {
                if($nonce->PublicKey() && $nonce->PublicKey()->Member()) {
                    $nonce->PublicKey()->Member()->login();
                    return true;
                }else {
                    //Register
                    $form->sessionMessage('Not Registered', 'bad');
                    return false;
                }
            }else {
                $form->sessionMessage('Sqrl Response Not Verified', 'bad');
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
        $sqrlConfig->setQrHeight(self::config()->QRHeight);
        $sqrlConfig->setQrPadding(self::config()->QRPadding);
        $sqrlConfig->setSecure(self::config()->UseSecure);
        $sqrlConfig->setNonceMaxAge(self::config()->NonceMaxAge);
        $sqrlConfig->setDomain(parse_url(Director::absoluteBaseURL(), PHP_URL_HOST));
        $sqrlConfig->setAuthenticationPath(parse_url(Director::absoluteBaseURL(), PHP_URL_PATH).'SQRLAuthentication/authenticate');
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
        }
        
        return self::$_sqrl;
    }
}
?>