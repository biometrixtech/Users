anatomy_id = 999
training_group_id = 333
example_user_data = {"email": "susie@smith.com",
                     "password": "ABC123456",
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
                          "phone_number": 3015551234,
                          "account_type": "pending",
                          "account_status": "active",
                     },
                     "role": "athlete",
                     "system_type": "1-sensor",
                     "injury_status": "healthy",
                     "injuries": {"current":
                                    {"type": "muscle-strain",
                                     "body_parts": [anatomy_id],
                                     "notes": "",
                                     "start_date": "5/1/2018",
                                     "days_missed": 15
                                     },
                                     "history": [
                                        {"type": "ligament-dislocation",
                                         "body_parts": [anatomy_id, anatomy_id],
                                         "notes": "",
                                         "start_date": "6/1/2017",
                                         "end_date": "9/1/2017",
                                         "days_missed": 20
                                        },
                                       {"type": "muscle-tear",
                                        "body_parts": [anatomy_id, ...],
                                        "notes": None,
                                        "start_date": "12/1/2016",
                                        "end_date": "1/1/2017",
                                        "days_missed": 15
                                        }
                                        ]
                                    },
                     "training_groups": [training_group_id, ...],
                     "sports": [{"name": "Lacrosse",
                                "positions": ["Goalie"],
                                "competition_levels": [{"competition_level": "NCAA Division II",
                                                          "start_date": "1/1/2015",
                                                          "end_date": "3/1/2018"
                                                         },
                                                          {"competition_level": "High School",
                                                          "start_date": "9/1/2010",
                                                          "end_date": "5/1/2014"
                                                         }
                                                          ]
                                    },
                                    {"name": "Rugby",
                                     "positions": ["n/a"],
                                     "competition_levels": [{"competition_level": "High School",
                                                             "start_date": "9/1/2011",
                                                             "end_date": "6/1/2012"
                                                            }
                                                          ]
                                     }
                                ]
                     }
