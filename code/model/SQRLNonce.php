<?php
class SQRLNonce extends DataObject {
    private static $db=array(
                            'Nonce'=>'Varchar(64)',
                            'IP'=>'Varchar',
                            'Action'=>'Varchar',
                            'Related_Public_Key'=>'Varchar(44)',
                            'Verified'=>'Boolean'
                         );
    
    
    private static $defaults=array(
                                    'Verified'=>false
                                );
    
    private static $indexes=array(
                                'Nonce'=>true
                            );
    
    public function PublicKey() {
        return SQRLPublicKey::get()->filter('Key', $this->Related_Public_Key)->first();
    }
}
?>