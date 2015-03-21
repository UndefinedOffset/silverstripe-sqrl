<?php
class SQRLLoginForm extends MemberLoginForm {
    protected $authenticator_class='SQRLAuthenticator';
    
    /**
     * Constructor
     *
     * @param Controller $controller The parent controller, necessary to
     *                               create the appropriate form action tag.
     * @param string $name The method on the controller that will return this
     *                     form object.
     * @param FieldList|FormField $fields All of the fields in the form - a
     *                                   {@link FieldList} of {@link FormField}
     *                                   objects.
     * @param FieldList|FormAction $actions All of the action buttons in the
     *                                     form - a {@link FieldList} of
     *                                     {@link FormAction} objects
     * @param bool $checkCurrentUser If set to TRUE, it will be checked if a
     *                               the user is currently logged in, and if
     *                               so, only a logout button will be rendered
     * @param string $authenticatorClassName Name of the authenticator class that this form uses.
     */
    public function __construct($controller, $name, $fields = null, $actions = null, $checkCurrentUser = true) {
        if($checkCurrentUser && Member::currentUser() && Member::logged_in_session_exists()) {
            $fields=new FieldList(
                                    new HiddenField("AuthenticationMethod", null, $this->authenticator_class, $this)
                                );
            
            $actions=new FieldList(
                                    new FormAction("logout", _t('Member.BUTTONLOGINOTHER', "Log in as someone else"))
                                );
        }else {
            if(!$fields) {
                $sqrl=SQRLAuthenticator::getSQRL();
                $sqrlNonce=$sqrl->getNonce();
                
                
                
                $label=singleton('Member')->fieldLabel(Member::config()->unique_identifier_field);
                $fields=new FieldList(
                                        new LiteralField('sqrlLoginCode', '<div class="sqrlLogin"><a href="'.$sqrl->getURL().'"><img src="SQRLAuthentication/qr-code/'.$sqrlNonce.'" alt=""/></a></div>'),
                                        CompositeField::create(
                                                                new TextField("Email", $label, Session::get('SessionForms.MemberLoginForm.Email'), null, $this),
                                                                new PasswordField("Password", _t('Member.PASSWORD', 'Password'))
                                                            )->addExtraClass('standardLogin'),
                                        new HiddenField("AuthenticationMethod", null, $this->authenticator_class, $this),
                                        new HiddenField('SQRLNonce', 'SQRLNonce', $sqrlNonce)
                                    );
                
                if(Security::config()->autologin_enabled) {
                    $fields->push(new CheckboxField('Remember', _t('Member.REMEMBERME', 'Remember me next time?')));
                }
            }
            
            if(!$actions) {
                $actions=new FieldList(
                                        new FormAction('dologin', _t('Member.BUTTONLOGIN', "Log in")),
                                        new LiteralField('forgotPassword', '<p id="ForgotPassword"><a href="Security/lostpassword">'._t('SQRLLoginForm.BUTTONLOSTPASSWORD', "Recover my Account, I've lost my authenticator or Password") . '</a></p>')
                                    );
            }
        }
        
        parent::__construct($controller, $name, $fields, $actions, $checkCurrentUser);
        
        $this->validator=null;
    }
}
?>