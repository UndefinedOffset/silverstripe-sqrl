<?php
use Trianglman\Sqrl\SqrlValidate;
use Tingleman\Sqrl\SqrlConfiguration;

class SQRLAuthentication extends Controller {
    private static $allowed_actions=array(
                                        'authenticate',
                                        'qr_code'
                                    );
    
    
    public function qr_code() {
        if(empty($this->urlParams['ID'])) {
            return $this->httpError(403);
        }
        
        //Disable ContentNegotiator
        $previousSetting=Config::inst()->get('ContentNegotiator', 'enabled');
        Config::inst()->update('ContentNegotiator', 'enabled', false);
        
        
        $qrCode=new Endroid\QrCode\QrCode();
        $qrCode->setText($this->_buildUrl());
        $qrCode->setSize(SQRLAuthenticator::config()->QRHeight);
        $qrCode->setPadding(SQRLAuthenticator::config()->QRPadding);
        
        
        $this->response->addHeader('Content-Type', 'image/png');
        $qrCode->render(null, 'png');
        
        
        Config::inst()->update('ContentNegotiator', 'enabled', $previousSetting);
    }
    
    public function authenticate() {
        $sqrlConfig=SQRLAuthenticator::getSQRLConfig();
        $sqrlStore=new SilverStripeSQRLStore();
        
        if(extension_loaded("ellipticCurveSignature")) {
            $sigValidator=new \Trianglman\Sqrl\EcEd25519NonceValidator();
        }else {
            $sigValidator=new \Trianglman\Sqrl\Ed25519NonceValidator();
        }
        
        $validator=new \Trianglman\Sqrl\SqrlValidate($sqrlConfig, $sigValidator, $sqrlStore);
        
        //initialize the request handler
        $requestResponse=new \Trianglman\Sqrl\SqrlRequestHandler($sqrlConfig, $validator, $sqrlStore, SQRLAuthenticator::getSQRL());
        
        $postData=$this->request->postVars();
        if(empty($postData)) {
            parse_str(file_get_contents('php://input'), $postData);
        }
        
        $requestResponse->parseRequest($this->request->getVars(), $postData, $_SERVER);
        
        
        //Send Response
        $requestResponse->sendResponse();
    }
    
    /**
     * Generates the URL to display in the QR code
     * @return {string}
     */
    protected function _buildUrl() {
        $urlInfo=parse_url(Director::absoluteBaseURL());
        
        $url=(SQRLAuthenticator::config()->UseSecure ? 's' : '').'qrl://'.$urlInfo['host'].$urlInfo['path'].'SQRLAuthentication/authenticate';
        $currentPathParts=parse_url($url);
        
        if(!empty($currentPathParts['query'])) {
            $pathAppend='&nut=';
        }else {
            $pathAppend='?nut=';
        }

        return $url.$pathAppend.$this->urlParams['ID'];
    }
}
?>