class User < ActiveRecord::Base

  # Include default devise modules. Others available are:
  # :token_authenticatable, :confirmable, :lockable and :timeoutable
  devise :database_authenticatable, :ldap_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable# , :validatable

  # Setup accessible (or protected) attributes for your model
  attr_accessible :email, :password, :password_confirmation
  
  def valid_password?(password)
    super
  rescue BCrypt::Errors::InvalidHash => e
    false
  end
end
