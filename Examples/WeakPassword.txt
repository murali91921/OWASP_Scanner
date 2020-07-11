using System;
using System.Text;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel;


namespace WeakPassword
{
    public class UserLogin
    {
        [Required (ErrorMessage="Login {0} is required")]
        [StringLength (100,MinimumLength=3)]
        [DataType(DataType.Text)]
        public string Name { get; set; }

        [Required (ErrorMessage="Login {0} is required")]
        [StringLength (50,MinimumLength:6,
        ErrorMessage="Password Should be minimum 6 characters and a maximum of 50 characters")]
        [DataType(DataType.Password)]
        public string Password_Weak_Colon { get; set; }

        [Required (ErrorMessage="Login {0} is required")]
        [StringLength (50,MinimumLength=7,
        ErrorMessage="Password Should be minimum 6 characters and a maximum of 50 characters")]
        [DataType(DataType.Password)]
        public string Password_Weak_Equal { get; set; }

        [Required (ErrorMessage="Login {0} is required")]
        [StringLength (50,MinimumLength=10,
        ErrorMessage="Password Should be minimum 6 characters and a maximum of 50 characters")]
        [DataType(DataType.Password)]
        public string Password_Strong { get; set; }

        [DataType(DataType.Password)]
        public string Password_NoMinimum { get; set; }

        [Range(18,99, ErrorMessage="Age should be between 18 and 99")]
        public int Age { get; set; }

        [DataType(DataType.PhoneNumber)]
        [Phone]
        public string PhoneNumber { get; set; }

        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        public string Email { get; set; }
    }
}
