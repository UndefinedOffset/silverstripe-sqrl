<?php
class SQRLPublicKey extends DataObject {
    private static $db=array(
                            'Public_Key'=>'Varchar(44)',
                            'VUK'=>'Varchar(44)',
                            'SUK'=>'Varchar(44)',
                            'Disabled'=>'Boolean'
                         );
    
    private static $has_one=array(
                                'Member'=>'Member'
                             );
    
    private static $indexes=array(
                                'Public_Key'=>array('type'=>'unique', 'value'=>'Public_Key'),
                                'VUK'=>true
                            );
    
    private static $defaults=array(
                                    'Disabled'=>false
                                );
    
    
}
?>