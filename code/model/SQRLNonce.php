<?php
class SQRLNonce extends DataObject {
    private static $db=array(
                            'Nonce'=>'Varchar(64)',
                            'IP'=>'Varchar',
                            'Action'=>'Varchar',
                            'Related_Public_Key'=>'Varchar(44)',
                            'Verified'=>'Boolean',
                            'KillSession'=>'Boolean',
                            'OrigNonce'=>'Varchar(64)'
                         );
    
    
    private static $defaults=array(
                                    'Verified'=>false,
                                    'KillSession'=>false
                                );
    
    private static $indexes=array(
                                'Nonce'=>array('type'=>'unique', 'value'=>'Nonce')
                            );
    
    public function PublicKey() {
        return SQRLPublicKey::get()->filter('Key', $this->Related_Public_Key)->first();
    }
}
?>