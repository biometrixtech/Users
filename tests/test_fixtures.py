example_user_data = {"email": "susie123@smith.com",
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
