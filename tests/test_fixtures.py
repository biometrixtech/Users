example_user_data = {"email": "steve1234@gmail.com",
                     "password": "ABC123456",
                     "role": "athlete",
                     "system_type": "1-sensor",
                     "injury_status": "healthy",
                     "onboarding_status": ["account_setup"],
                     "biometric_data": {
                                        "gender": "male",
                                        "height": {"m": 1.5},
                                        "mass": {"kg": 60}
                     },
                     "personal_data": {
                          "birth_date": "03/05/1992",
                          "zip_code": "00321",
                          "first_name": "Susie",
                          "last_name": "Smith",
                          "phone_number": "3015551234",
                          "account_type": "pending",
                          "account_status": "active",
                     },
                     "injuries": {"current":
                                    {"type": "muscle-strain",
                                     "body_parts": ["knee"],
                                     "notes": "",
                                     "start_date": "5/1/2018",
                                     "days_missed": 15
                                     },
                                     "history": [
                                        {"type": "ligament-dislocation",
                                         "body_parts": ["hip", "thigh"],
                                         "notes": "",
                                         "start_date": "6/1/2017",
                                         "end_date": "9/1/2017",
                                         "days_missed": 20
                                        },
                                       {"type": "muscle-tear",
                                        "body_parts": ["quad"],
                                        "notes": None,
                                        "start_date": "12/1/2016",
                                        "end_date": "1/1/2017",
                                        "days_missed": 15
                                        }
                                        ]
                                    }
                     }


example_user_data_2 = {
    "email": "tests000014@biometrixtech.com",
    "password": "Fathom123!",
    "biometric_data": {
        "sex": "male",
        "height": {"m": 1.5},
        "mass": {"kg": 98}
    },
    "personal_data": {
      "birth_date": "01/01/1990",
      "first_name": "Vir",
      "last_name": "Desai",
      "phone_number": "1234567890",
      "account_type": "free",
      "account_status": "active",
      "zip_code": "27701"
    },
    "role": "athlete",
    "system_type": "1-sensor",
    "injury_status": "healthy_chronically_injured" #,
    # "onboarding_status": "account_setup"
}

example_user_data_3 = {}
