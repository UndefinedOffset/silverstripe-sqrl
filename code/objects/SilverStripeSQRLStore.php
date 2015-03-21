<?php
class SilverStripeSQRLStore extends Object implements Trianglman\Sqrl\SqrlStoreInterface {
    /**
     * Updates a user's key information after an identity update action
     *
     * @param string $oldKey The key getting new information
     * @param string $newKey The authentication key replacing the old key
     * @return void
     */
    public function updateIdentityKey($oldKey, $newKey) {
        $key=SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($oldKey));
        if(!empty($key) && $key!==false && $key->ID>0) {
            $key->Public_Key=$newKey;
            $key->write();
        }
    }
    
    /**
     * Checks the status of an identity key
     *
     * @param string $key
     * @return int One of the class key status constants
     */
    public function checkIdentityKey($key) {
        $key=SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($key));
        if(!empty($key) && $key!==false && $key->ID>0) {
            return ($key->Disabled==true ? self::IDENTITY_LOCKED:self::IDENTITY_ACTIVE);
        }
        
        return self::IDENTITY_UNKNOWN;
    }
    
    /**
     * Activates a session
     *
     * @param string $requestNut The nut of the current request that is being logged in
     * @return void
     */
    public function logSessionIn($requestNut) {
        $key=SQRLNonce::get()->filterAny(array(
                                                'Nonce'=>Convert::raw2sql($requestNut),
                                                'OrigNonce'=>Convert::raw2sql($requestNut)
                                            ));
        
        if(!empty($key) && $key!==false && $key->ID>0) {
            $key->Verified=true;
            $key->write();
        }
    }
    
    /**
     * Retrieves information about the supplied nut
     *
     * @param string $nut    The nonce to retrieve information on
     * @return array:
     * 'tif'=> int The tif stored with the nut (0 for first request nuts)
     * 'originalKey'=> string The key associated with the nut, if any
     * 'originalNut'=> string The nut that came before this one in the transaction, if any
     * 'createdDate'=> \DateTime The time the nut was created
     * 'nutIP'=> string the IP address that requested the nut
     * 'sessionId'=> string the session ID for the nut [this is only required in stateless nuts]
     */
    public function getNutDetails($nut) {
        $key=SQRLNonce::get()->filter('Nonce', Convert::raw2sql($requestNut));
        if(!empty($key) && $key!==false && $key->ID>0) {
            return array(
                        'tif'=>$nonce->Action,
                        'originalKey'=>$nonce->Related_Public_Key,
                        'originalNut'=>$nonce->OrigNonce,
                        'createdDate'=>new \DateTime($nonce->Created),
                        'nutIP'=>$nonce->IP
                    );
        }
        
        return false;
    }
    
    /**
     * Flags a session as no longer valid.
     *
     * @param string $requestNut The nut of the curret request related to the session
     * to be destroyed
     * @return void
     */
    public function endSession($requestNut) {
        $key=SQRLNonce::get()->filter('Nonce', Convert::raw2sql($requestNut));
        if(!empty($key) && $key!==false && $key->ID>0) {
            $key->KillSession=true;
            $key->write();
        }
    }
    
    /**
     * Unlocks an authentication key allowing future authentication
     *
     * @param string $key The authentication key to lock
     * @return void
     */
    public function unlockIdentityKey($key) {
        $key=SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($key));
        if(!empty($key) && $key!==false && $key->ID>0) {
            $key->Disabled=false;
            $key->write();
        }
    }
    
    /**
     * Gets the current active nonce for the user's session if there is any
     *
     * @return string
     */
    public function getSessionNonce() {
        return Session::get('SQRL.nut');
    }
    
    /**
     * Gets an identity's VUK value in order for the client to use the Identity Unlock protocol
     *
     * @param string $key The identity key
     * @return string The VUK value
     */
    public function getIdentityVUK($key) {
        $key=SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($key));
        if(!empty($key) && $key!==false && $key->ID>0) {
            return $key->VUK;
        }
        
        return false;
    }
    
    /**
     * Gets an identity's SUK value in order for the client to use the Identity Unlock protocol
     *
     * @param string $key The identity key
     * @return string The SUK value
     */
    public function getIdentitySUK($key) {
        $key=SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($key));
        if(!empty($key) && $key!==false && $key->ID>0) {
            return $key->SUK;
        }
        
        return false;
    }
    
    /**
     * Stores a nonce and the related information
     *
     * @param string $nonce  The nonce to store
     * @param int $action The tif related to the nonce
     * @param string $key [Optional] The identity key related to the nonce
     * @param string $previousNonce [Optional] The previous nonce related to the nonce
     * @return void
     */
    public function storeNonce($nonce, $action, $key='', $previousNonce='') {
        $nonceObj=new SQRLNonce();
        $nonceObj->Nonce=$nonce;
        $nonceObj->IP=(array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER) ? $_SERVER['HTTP_X_FORWARDED_FOR']:$_SERVER['REMOTE_ADDR']);
        $nonceObj->Action=$action;
        $nonceObj->Related_Public_Key=$key;
        $nonceObj->write();
        
        if(empty($previousNonce)) {
            $sessionNut=Session::get('SQRL.nut');
            if(empty($sessionNut)) {
                Session::set('SQRL.nut', $nonce);
            }
        }
    }
    
    /**
     * Stores a new identity key along with the Identity Lock information
     *
     * @param string $key
     * @param string $suk
     * @param string $vuk
     * @return void
     */
    public function createIdentity($key,$suk,$vuk) {
        $pubKey=new SQRLPublicKey();
        $pubKey->Public_Key=$key;
        $pubKey->SUK=$suk;
        $pubKey->VUK=$vuk;
        $pubKey->write();
    }
    
    /**
     * Locks an authentication key against further use until a successful unlock
     *
     * @param string $key The authentication key to lock
     * @return void
     */
    public function lockIdentityKey($key) {
        $key=SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($key));
        if(!empty($key) && $key!==false && $key->ID>0) {
            $key->Disabled=true;
            $key->write();
        }
    }
}
?>