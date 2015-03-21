<?php
use Trianglman\Sqrl\SqrlException;
use Trianglman\Sqrl\SqrlRequestHandlerInterface;

class SilverStripeSQRLStore implements Trianglman\Sqrl\SqrlStoreInterface {
    /**
     * Retrieves information about the supplied nut
     * @param {string} $nut The nonce to retrieve information on
     * @param {array} $values Not used
     * @return {array}
     */
    public function retrieveNutRecord($nut, $values = null) {
        return array_change_key_case(SQRLNonce::get()->filter('Nonce', Convert::raw2sql($nut))->first()->toArray());
    }
    
    /**
     * Stores a nonce and the related information
     * @param {string} $nut The nonce to store
     * @param {int} $ip The IP of the user the nonce is associated with
     * @param {int} $type [Optional] The action this nonce is associated with
     * @param {string} $key [Optional] The authentication key associated with the nonce action
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeNut($nut, $ip, $type = SqrlRequestHandlerInterface::INITIAL_REQUEST, $key = null) {
        $obj=new SQRLNonce();
        $obj->Nonce=$nut;
        $obj->IP=$ip;
        $obj->Action=$type;
        
        if(!empty($key)) {
            $obj->Related_Public_Key=$key;
        }
        
        $obj->write();
    }
    
    /**
     * Stores a user's authentication key
     * @param {string} $key The authentication key to store
     * @return {int} The authentication key's ID
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeAuthenticationKey($key) {
        $obj=new SQRLPublicKey();
        $obj->Public_Key=$key;
        $obj->write();
        
        return $obj->ID;
    }
    
    /**
     * Returns information about a supplied authentication key
     * @param {string} $key The key to retrieve information on
     * @param {array} $values Not used
     * @return {array} Record map
     */
    public function retrieveAuthenticationRecord($key, $values = null) {
        return array_change_key_case(SQRLPublicKey::get()->filter('Public_Key', Convert::raw2sql($key))->filter()->toArray());
    }
    
    /**
     * Attaches a server unlock key and verify unlock key to an authentication key
     * @param {string} $key The authentication key to associate the data with
     * @param {string $suk The server unlock key to associate
     * @param {string} $vuk the verify unlock key to associate
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeIdentityLock($key, $suk, $vuk) {
        $obj=SQRLPublicKey::get()->filter('PublicKey', Convert::raw2sql($key))->first();
        if(empty($obj) && $obj!==false && $obj->ID>0) {
            throw new SqrlException('Could not find the public key record');
            return;
        }
        
        $obj->SUK=$suk;
        $obj->VUK=$vuk;
        $obj->write();
    }
    
    /**
     * Updates a user's key information after an identity unlock action
     * @param {string} $oldKey The key getting new information
     * @param {string} $newKey [Optional] The authentication key replacing the old key
     * @param {string} $newSuk [Optional] The replacement server unlock key
     * @param {string} $newVuk [Optional] The replacement verify unlock key
     *
     * @throws SqrlException If there is a database issue
     */
    public function migrateKey($oldKey, $newKey=null, $newSuk=null, $newVuk=null) {
        $obj=SQRLPublicKey::get()->filter('PublicKey', Convert::raw2sql($key))->first();
        if(empty($obj) && $obj!==false && $obj->ID>0) {
            throw new SqrlException('Could not find the public key record');
            return;
        }
        
        //Replace Key
        if(!empty($newKey)) {
            $obj->PublicKey=$key;
            $obj->Disabled=false;
        }
        
        //Replace SUK
        if(!empty($newSuk)) {
            $obj->SUK=$newSuk;
        }
        
        //Replace VUK
        if(!empty($newVuk)) {
            $obj->VUK=$newVuk;
        }
        
        $obj->write();
    }
    
    /**
     * Locks an authentication key against further use until a successful unlock
     * @param {string} $key The authentication key to lock
     *
     * @throws SqrlException If there is a database issue
     */
    public function lockKey($key) {
        $obj=SQRLPublicKey::get()->filter('PublicKey', Convert::raw2sql($key))->first();
        if(empty($obj) && $obj!==false && $obj->ID>0) {
            throw new SqrlException('Could not find the public key record');
            return;
        }
        
        $obj->Disabled=true;
        $obj->write();
    }
    
    /**
     * Sets the table name of the authentication key information (Not used!)
     * @private
     */
    public function setPublicKeyTable($table) {
        user_error('Not used', E_USER_ERROR);
    }
    
    /**
     * Sets the database configuration (Not used!)
     * @private
     */
    public function configureDatabase($dsn, $username = '', $pass = '') {
        user_error('Not used', E_USER_ERROR);
    }
    
    /**
     * Directly set the database connection rather than letting SqrlStore create one (Not used!)
     * @private
     */
    public function setDatabaseConnection(\PDO $db) {
        user_error('Not used', E_USER_ERROR);
    }
    
    /**
     * Loads a configuration file from the supplied path (Not used!)
     * @private
     */
    public function loadConfigFromJSON($filePath) {
        user_error('Not used', E_USER_ERROR);
    }
    
    /**
     * Sets the table name of the nut information (Not used!)
     * @private
     */
    public function setNonceTable($table) {
        user_error('Not used', E_USER_ERROR);
    }
}
?>
