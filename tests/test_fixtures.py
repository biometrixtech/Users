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
                                        "body_parts": [anatomy_id],
                                        "notes": None,
                                        "start_date": "12/1/2016",
                                        "end_date": "1/1/2017",
                                        "days_missed": 15
                                        }
                                        ]
                                    },
                     "training_groups": [training_group_id],
                     "training_schedule": [{"practice": {"days_of_week": "Mon,Tue,Wed,Thu,Fri,Sat",
                                                        "duration_minutes": 90},
                                            "competition": {"days_of_week": "Sun",
                                                            "duration_minutes": 90
                                                            }
                                           }],
                     "training_strength_conditioning": [{"activity": "weight_lifting",
                                                         "days_of_week": "Tue,Thu",
                                                         "duration_minutes": 30},
                                                        {"activity": "yoga",
                                                         "days_of_week": "Fri",
                                                         "duration_minutes": 60}
                                                        ],
                     "sports": [{"name": "Lacrosse",
                                 "positions": ["Goalie"],
                                 "competition_level": "NCAA Division II",
                                 "start_date": "1/1/2015",
                                 "end_date": "3/1/2018",
                                 "season_start_month": "January",
                                 "season_end_month": "May"
                                 },
                                 {"name": "Rugby",
                                  "positions": ["n/a"],
                                  "competition_level": "High School",
                                  "start_date": "9/1/2011",
                                  "end_date": "6/1/2012",
                                  "season_start_month": "August",
                                  "season_end_month": "November"
                                  }
                                ]
                     }
