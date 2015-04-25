class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  ROLES = %w{ admin teacher student }

  validates :role,
	inclusion: { in: ROLES, message: "%{value} is not a valid role" }

	#Instance methods

	def admin?
		role == admin
	end

	def manager?
		role == teacher
	end

	def reader?
		role == reader
	end

end
