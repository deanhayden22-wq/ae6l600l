# AE5L600L — ECUFlash Def Table Inventory

Generated from def files in `definitions/`. Inheritance: `32BITBASE` → `AE5L600L 2013 USDM Impreza WRX MT` → `AE5L600L MerpMod SD`.

**Total unique tables visible to this ROM: 1350**

Source legend: B = 32BITBASE, R = AE5L600L (ROM-specific), M = MerpMod SD. `*` = overrides an inherited table.

## (uncategorized)  (97 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| 'Base Timing Idle Minimum' active | `` | Static Y Axis |  | B |
| 'Base Timing Idle' active | `` | Static Y Axis |  | B |
| 'Requested Torque (Accelerator Pedal)' to 'Requested Torque Base (RPM)' | `f9484` |  |  | R* |
| 'Timing Compensation (MRP)' + 'Timing Compensation (IAT)' | `ccd18` |  |  | R* |
| 'Timing Compensation B (IAT)' | `` | Static Y Axis |  | B |
| (Condition) - Result | `` | Static Y Axis |  | B* |
| A/F Learning #1 and #2 Store/Apply Ranges | `` | Static Y Axis |  | B |
| A/F Learning Limits | `` | Static Y Axis |  | B* |
| A/F Learning Store/Apply Ranges | `` | Static Y Axis |  | B |
| APS Voltage to Atmospheric Pressure | `` | Static Y Axis |  | B* |
| Accelerator Pedal Angle | `f9e60` |  |  | R* |
| Active Decay | `` | Static Y Axis |  | B |
| Active Primary Open Loop Fueling | `` | Static Y Axis |  | B |
| Atmospheric Pressure | `c36f8` |  |  | R* |
| Atmospheric Pressure (mmHg) | `db434` | Y Axis | MerpMod_AtmPressure_mmHg | M |
| Battery Output | `d104c` |  |  | R* |
| Battery Voltage | `` | X Axis | rawecuvalue | B* |
| Battery Volts | `d91cc` |  |  | R* |
| Below Vehicle Speed Disable Threshold | `` | Static Y Axis |  | B |
| Boost Control | `` | Static Y Axis |  | B* |
| Boost Error | `cd128` |  |  | R* |
| Capped Limit | `` | Static Y Axis |  | B* |
| Clear Applied Tip-in Cumulative Throttle | `` | Static Y Axis |  | B |
| Clear Tip-in Enrichment Applied Counter | `` | Static Y Axis |  | B |
| Coolant Temp | `d7e38` |  |  | R* |
| Coolant Temp Sensor | `d8ddc` |  |  | R* |
| Coolant Temperature | `CC624` |  |  | R* |
| Delay Value | `` | Static Y Axis |  | B* |
| Delay Values | `` | Static Y Axis |  | B |
| Disable 'CL Fueling Target Compensation (ECT)' | `` | Static Y Axis |  | B |
| Disable Tip-in Enrichment | `` | Static Y Axis |  | B* |
| Engine Coolant Temperature | `` | Static X Axis | RPM | B* |
| Engine Load | `d5434` |  |  | R* |
| Engine Speed | `ce580` | X Axis | RPM | R* |
| Engine Speed (RPM) | `db4f8` | Y Axis | MerpMod_RPM | M* |
| Engine Speed Delta | `d8060` |  |  | R* |
| Exhaust Gas Temperature Sensor | `` | Y Axis | volts | B |
| Exhaust VVT Error | `d11d0` |  |  | R* |
| Feedback Knock Correction | `` | Static Y Axis |  | B* |
| Fine Correction Stored/Applied Load Ranges | `` | Static Y Axis |  | B* |
| Fine Correction Stored/Applied RPM Ranges | `` | Static Y Axis |  | B* |
| Front Oxygen Sensor | `d8d74` |  |  | R* |
| Fuel Efficiency Correction | `` | Static Y Axis |  | B |
| Fuel Pump Duty | `` | Static Y Axis |  | B* |
| Fuel Temp Sensor | `d8fac` |  |  | R* |
| Gear | `f9888` |  |  | R* |
| Gear Thresholds | `` | Static Y Axis |  | B* |
| Idle Airflow Target | `` | X Axis | MassAirflow(g/s)1 | B |
| Idle Speed Error | `d801c` |  |  | R* |
| Idle Speed Target | `` | Y Axis | RPM | B* |
| Injector Pulse Width | `d3988` | Y Axis |  | R* |
| Intake Temp Sensor | `d8ebc` |  |  | R* |
| Intake Temperature | `d3860` |  |  | R* |
| Intake VVT Error | `cf9ec` |  |  | R* |
| Last Calculated Base Pulse Width | `d0c64` |  |  | R* |
| Limits | `` | Static Y Axis |  | B |
| MAF sensor | `d8bc4` |  |  | R* |
| MAP (kPa abs) | `db4d0` | X Axis | MerpMod_MAP_kPa | M* |
| MPS Voltage to Manifold Absolute Pressure | `` | Static Y Axis |  | B* |
| Manifold Pressure | `c3cd8` |  |  | R* |
| Manifold Pressure Sensor | `` | Static Y Axis |  | B |
| Manifold Pressure Sensor CEL | `` | Static Y Axis |  | B |
| Manifold Relative Pressure | `` | Y Axis | psirelativesealevel | B* |
| Mass Airflow | `c3b90` |  |  | R* |
| Mode Determination (coolant temp change) | `` | Static Y Axis |  | B* |
| Mode Determination (vehicle speed change) | `` | Static Y Axis |  | B |
| Multiplier Determination | `` | Static Y Axis |  | B |
| OL to CL Transition | `` | Static Y Axis |  | B* |
| OverRun | `` | Static Y Axis |  | B* |
| Per Cylinder Timing Compensation | `` | Static Y Axis |  | B* |
| Potential Fine Correction Stored Value Adjustments | `` | Static Y Axis |  | B* |
| Potential Rough Correction (IAM) Learning | `` | Static Y Axis |  | B |
| Potential Rough Correction Learning (IAM) | `` | Static Y Axis |  | B* |
| RPM | `` | Static Y Axis |  | B* |
| Requested Torque | `c0ee8` |  |  | R* |
| Rev Limit Fuel Cut | `` | Static Y Axis |  | B* |
| Rev Limit Fuel Resume | `` | Static Y Axis |  | B* |
| Select State | `` | Y Axis | rawecuvalue | B* |
| Smoothed MAF | `` | X Axis | g/s | B |
| Speed Limit Fuel Cut (Transmission) | `` | Static Y Axis |  | B |
| Speed Limiter Fuel Cut | `` | Static Y Axis |  | B* |
| Switch to Failsafe Fueling Map | `` | Static Y Axis |  | B |
| TPS Opening % | `` | Y Axis | TargetThrottlePlateOpeningAngle(%)1 | R |
| Target Throttle Plate Position % | `` | X Axis | % | B |
| Throttle Angle Change | `ced74` |  |  | R* |
| Throttle Plate Opening Angle | `ccd88` |  |  | R* |
| Throttle Reduction | `` | Static Y Axis |  | B* |
| Throttle Table Selection | `` | Static Y Axis |  | B |
| Timing Compensation (IAT) | `` | Static Y Axis |  | B* |
| Timing Compensation Per Gear Activation Load | `` | Static Y Axis |  | B |
| Timing Compensation Per Gear Activation RPM | `` | Static Y Axis |  | B |
| Tip-in Enrichment | `` | Static Y Axis |  | B* |
| Turbo Dynamics Active Correction | `` | Static Y Axis |  | B* |
| Vehicle Speed | `` | X Axis | VehicleSpeed(MPH) | B* |
| Volts | `` | X Axis | RPM | B* |
| Y | `` | Y Axis | Knock | B* |
| limits | `` | Static X Axis |  | R |

## AVCS / Cam Timing  (4 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Exhaust Duty Correction A | `d121c` |  |  | R* |
| Intake Cam Advance Angle Cruise (AVCS) | `da96c` |  |  | R* |
| Intake Cam Advance Angle Non-Cruise (AVCS) | `dac34` |  |  | R* |
| Intake Duty Correction A | `cfa38` |  | Intake Duty Correction (uint8) | R* |

## Alpha A/F #1 Learning Thresholds  (2 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| A/F #1 Learning Max Threshold | `` | 1D | MassAirflow(g/s)1 | B |
| A/F #1 Learning Min Threshold | `` | 1D | MassAirflow(g/s)1 | B |

## Alpha Engine Load Limit B Multiplier  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Engine Load Limit B Maximum (RPM) - Multiplier | `aae20` | 2D | rawecuvalueverbose | R* |

## Alpha Front O2 Sensor Smoothing  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Front AF Sensor Smoothing Table | `` | 3D | SmoothingFactor | B |

## Alpha Fuel Pump  (2 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Fuel Pump Duty High Injector Duty Cycle | `` | 3D | IDC | B |
| Fuel Pump Duty Medium Injector Duty Cycle | `` | 3D | IDC | B |

## Alpha Hotstart  (24 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Hotstart Enrichment Decay Delay | `` | 1D | Hotstart Counter uint16 | B |
| Hotstart Enrichment Decay Step | `` | 1D | Hotstart Enrichment | B |
| Hotstart High Enrichment Activation Threshold (Coolant Temperature) | `` | 1D | CoolantTemp(DegreesF) | B |
| Hotstart High Enrichment Activation Threshold (Intake Air Temperature) | `` | 1D | DegreesF | B |
| Hotstart Low Enrichment Activation Threshold (Coolant Temperature) | `` | 1D | CoolantTemp(DegreesF) | B |
| Hotstart Low Enrichment Activation Threshold (Minimum Intake Air Temperature) | `` | 1D | DegreesF | B |
| Hotstart Maximum Non-Idle Enrichment Delay | `` | 1D | Hotstart Counter uint16 | B |
| Hotstart Minimum Enrichment (During Delay and Runtime) | `` | 1D | Hotstart Enrichment | B |
| Hotstart Minimum Enrichment Limit Runtime | `` | 1D | Hotstart Counter uint16 | B |
| Initial Hotstart Enrichment (High) | `` | 1D | Hotstart Enrichment | B |
| Initial Hotstart Enrichment (Low) | `` | 1D | Hotstart Enrichment | B |
| Maximum Non-Idle Hotstart Enrichment (Post Delay) | `` | 1D | Hotstart Enrichment | B |
| hot_restart_enrich_decay_delay | `` | 1D | Alpha Hotstart 2 | B |
| hot_restart_enrich_decay_step_value | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_initial_high | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_initial_high_activat_min_coolant_temp | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_initial_high_activat_min_intake_temp | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_initial_low | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_initial_low_activat_min_coolant_temp | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_initial_low_activat_min_intake_temp | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_max_non_idle | `` | 1D | Alpha Hotstart 1 | B |
| hot_restart_enrich_max_non_idle_activation_max_run_time | `` | 1D | Alpha Hotstart 2 | B |
| hot_restart_enrich_min_lim_activat_max_run_time | `` | 1D | Alpha Hotstart 2 | B |
| hot_restart_enrich_min_limit | `` | 1D | Alpha Hotstart 1 | B |

## Alpha Idle Control  (11 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Idle Airflow Min Target Decel Adder (RPM) | `` | 2D | AirflowAdder | B |
| Idle Airflow Min Target Decel Adder A | `` | 2D | AirflowAdder | B |
| Idle Airflow Min Target Decel Adder Active Veh Speed B | `` | 1D | VehicleSpeed(MPH) | B |
| Idle Airflow Min Target Decel Adder B | `` | 2D | AirflowAdder | B |
| Idle Airflow Min Target Decel Initial Idle Min Airflow B | `` | 1D | rawecuvalue | B |
| Ignition Timing Compensation Idle Target In Error Range A | `` | 3D | Idle Ignition Timing | B |
| Ignition Timing Compensation Idle Target In Error Range B | `` | 3D | Idle Ignition Timing | B |
| Ignition Timing Compensation Idle Target Load Change A | `` | 3D | Idle Ignition Timing | B |
| Ignition Timing Compensation Idle Target Load Change B | `` | 3D | Idle Ignition Timing | B |
| Ignition Timing Compensation Idle Target Out of Error Range A | `` | 3D | Idle Ignition Timing | B |
| Ignition Timing Compensation Idle Target Out of Error Range B | `` | 3D | Idle Ignition Timing | B |

## Alpha OverRun Fueling  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Overrun Fueling Cut Counter RPM Threshold_ | `` | 2D | RPM | B |

## Alpha TPS  (12 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Alpha TPS Fuel Adder Activation Min Load | `` | 3D | EngineLoad(g/rev) | B |
| TPS_Related_Fuel_Activation_Min_TPS_Target_Delta_Hysteresis | `` | 1D | ThrottlePlateOpeningAngle(%) | B |
| TPS_Related_Fuel_Adder_Activation_Min_Coolant_Temp | `` | 2D | rawecuvalue | B |
| TPS_Related_Fuel_Adder_Activation_Min_Run_Time | `` | 1D | TPS | B |
| TPS_Related_Fuel_Adder_High_A | `` | 1D | rawecuvalue | B |
| TPS_Related_Fuel_Adder_High_B | `` | 1D | rawecuvalue | B |
| TPS_Related_Fuel_Adder_Low_A | `` | 1D | rawecuvalue | B |
| TPS_Related_Fuel_Adder_Low_B | `` | 1D | rawecuvalue | B |
| TPS_Related_Fuel_Adder_Low_High_Switch_Coolant | `` | 2D | rawecuvalue | B |
| TPS_Related_Fuel_Adder_No_Delay_Disable_Load_Thresh_not_met | `` | 1D | rawecuvalue | B |
| Table_TPS_Related_Fuel_Adder_Activation_Min_Load | `` | 3D | EngineLoad(g/rev) | B |
| Table_TPS_Related_Fuel_Adder_Activation_Min_TPS_Target_Delta | `` | 2D | TPS Throttle | B |

## Alpha Transient Fueling (Tau)  (21 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Input A Rising Load Activation ECT Load 1 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 10 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 11 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 12 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 13 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 14 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 2 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 3 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 4 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 5 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 6 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 7 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 8 | `` | 3D | Tau | B |
| Input A Rising Load Activation ECT Load 9 | `` | 3D | Tau | B |
| Tau Input A Rising Load Activation A | `` | 3D | Tau | B |
| Tau Input A Rising Load Activation B | `` | 3D | Tau | B |
| Tau Input A Rising Load Activation C | `` | 3D | Tau | B |
| Tau Input B Activation | `` | 2D | Tau | B |
| Tau Input B Activation (Engine Load) | `` | 2D | Tau | B |
| Tau Input B Activation A | `` | 2D | Tau | B |
| Tau Input B Activation B | `` | 2D | Tau | B |

## Alpha Variable Valve Timing (AVCS)  (6 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Exhaust Duty Correction B | `` | 3D | Intake Duty Correction | B |
| Exhaust Duty Correction C | `` | 3D | Intake Duty Correction | B |
| Exhaust Duty Correction D | `` | 3D | Intake Duty Correction | B |
| Intake Duty Correction B | `` | 3D | Intake Duty Correction | B |
| Intake Duty Correction C | `` | 3D | Intake Duty Correction | B |
| Intake Duty Correction D | `` | 3D | Intake Duty Correction | B |

## Boost Control  (32 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Boost Control Disable (IAM) | `c0bfc` |  |  | R* |
| Boost Control Disable Threshold | `d6724` | 1D | BoostThreshold | R |
| Boost Control Enable Threshold | `d6720` | 1D | BoostThreshold | R |
| Boost Feedback Filter Coefficient | `d6748` | 1D | CoefficientFloat | R |
| Boost Limit (Fuel Cut)_ | `d2560` |  |  | R* |
| Initial Wastegate Duty_ | `c1150` |  |  | R* |
| Initial/Max Wastegate Duty Compensation (Atm. Pressure) | `c0e7c` |  |  | R* |
| Initial/Max Wastegate Duty Compensation (ECT) | `c0cb4` |  |  | R* |
| Initial/Max Wastegate Duty Compensation (IAT) | `c0c94` |  |  | R* |
| Max Wastegate Duty Limit Post-Compensation | `14004` |  |  | R* |
| Max Wastegate Duty_ | `c0f58` |  |  | R* |
| Rev Limit Fuel Resume (Boost) | `cc518` |  |  | R* |
| TD Activation Thresholds (RPM) | `c0be8` |  |  | R* |
| TD Activation Thresholds (Target Boost)_ | `c0bd4` |  |  | R* |
| TD Integral Cumulative Range (WGDC Correction) | `c0bf0` |  |  | R* |
| TD Integral Negative Activation (Boost Error) | `c0bdc` |  |  | R* |
| TD Integral Negative Activation (Wastegate Duty) | `c0be4` |  |  | R* |
| TD Integral Negative Compensation (IAT) | `c0cd4` |  |  | R* |
| TD Integral Positive Activation (Boost Error) | `c0be0` |  |  | R* |
| TD Integral Positive Compensation (IAT) | `c0ce4` |  |  | R* |
| TD Proportional Compensation (IAT) | `c0cc4` |  |  | R* |
| Target Boost Compensation (1st Gear) | `c0c0c` |  |  | R* |
| Target Boost Compensation (1st Gear) Speed Disable | `c0c08` |  |  | R* |
| Target Boost Compensation (Atm. Pressure)_ | `c0ec4` |  |  | R* |
| Target Boost Compensation (ECT) | `c0cf4` |  |  | R* |
| Target Boost Compensation (IAT)_ | `c0e3c` |  |  | R* |
| Target Boost_ | `c1340` |  |  | R* |
| Tip-in Enrichment Compensation (Boost Error) | `cd14c` |  |  | R* |
| Turbo Dynamics Integral Negative | `c0d60` |  |  | R* |
| Turbo Dynamics Integral Positive | `c0d98` |  |  | R* |
| Turbo Dynamics Proportional | `c0d28` |  |  | R* |
| Wastegate Duty Cycle Frequency | `c009e` | 1D | 0.01 | R* |

## Boost Control - Limits  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Boost Limit (Fuel Cut) | `` | 2D | psiabsolute2 | B |

## Boost Control - Target  (20 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Target Boost | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (AT) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (KCA Additive B High) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (KCA Additive B Low) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (KCA Additive High) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (KCA Additive Low) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (KCA Alternate Mode) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost (MT) | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost A | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost B | `` | 3D | BoostTarget(psirelativesealevel) | B |
| Target Boost Compensation (Atm. Pressure) | `` | 2D | TargetBoost(psia)Compensation(%) | B |
| Target Boost Compensation (Atm. Pressure) Multiplier | `` | 2D | AtmosphericPressure(psi)Multiplier | B |
| Target Boost Compensation (Atm. Pressure) Multiplier (AT) | `` | 2D | AtmosphericPressure(psi)Multiplier | B |
| Target Boost Compensation (Atm. Pressure) Multiplier (MT) | `` | 2D | AtmosphericPressure(psi)Multiplier | B |
| Target Boost Compensation (Atm. Pressure) Multiplier Offset | `` | 2D | AtmosphericPressureMultiplierOffset | B |
| Target Boost Compensation (Atm. Pressure) Multiplier Offset (AT) | `` | 2D | AtmosphericPressureMultiplierOffset | B |
| Target Boost Compensation (Atm. Pressure) Multiplier Offset (MT) | `` | 2D | AtmosphericPressureMultiplierOffset | B |
| Target Boost Compensation (ECT)(AT) | `` | 2D | TargetBoost(psia)Compensation(%) | B |
| Target Boost Compensation (ECT)(MT) | `` | 2D | TargetBoost(psia)Compensation(%) | B |
| Target Boost Compensation (IAT) | `` | 2D | TargetBoost(psia)Compensation(%) | B |

## Boost Control - Turbo Dynamics  (10 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| TD Activation Thresholds (RPM)(AT) | `` | 2D | EngineSpeed(RPM)1 | B |
| TD Activation Thresholds (RPM)(MT) | `` | 2D | EngineSpeed(RPM)1 | B |
| TD Activation Thresholds (Target Boost) | `` | 2D | TargetBoost(psirelativesealevel) | B |
| TD Activation Thresholds (Target Boost)(AT) | `` | 2D | TargetBoost(psirelativesealevel) | B |
| TD Activation Thresholds (Target Boost)(MT) | `` | 2D | TargetBoost(psirelativesealevel) | B |
| TD Integral Negative Activation (Boost Error)(AT) | `` | 2D | BoostError(psi) | B |
| TD Integral Negative Activation (Boost Error)(MT) | `` | 2D | BoostError(psi) | B |
| TD Integral Positive Activation (Boost Error)(AT) | `` | 2D | BoostError(psi) | B |
| TD Integral Positive Activation (Boost Error)(MT) | `` | 2D | BoostError(psi) | B |
| TD Integral Positive Activation (Wastegate Duty) | `` | 2D | WastegateDutyCycle(%) | B |

## Boost Control - Wastegate  (26 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Initial Wastegate Duty | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (AT) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (KCA Additive B High) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (KCA Additive B Low) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (KCA Additive High) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (KCA Additive Low) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (KCA Alternate Mode) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty (MT) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty A | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial Wastegate Duty B | `` | 3D | WastegateDutyCycle(%)1 | B |
| Initial/Max Wastegate Duty Alternate Compensation (IAT) | `` | 2D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Initial/Max Wastegate Duty Compensation (Atm. Pressure)(AT) | `` | 3D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Initial/Max Wastegate Duty Compensation (Atm. Pressure)(MT) | `` | 3D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Initial/Max Wastegate Duty Compensation (ECT)(AT) | `` | 2D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Initial/Max Wastegate Duty Compensation (ECT)(MT) | `` | 2D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Initial/Max Wastegate Duty Compensation (IAT)(AT) | `` | 2D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Initial/Max Wastegate Duty Compensation (IAT)(MT) | `` | 2D | Initial/MaxWastegateDutyCompensation(%relative) | B |
| Max Wastegate Duty | `` | 3D | WastegateDutyCycle(%)1 | B |
| Max Wastegate Duty (AT) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Max Wastegate Duty (MT) | `` | 3D | WastegateDutyCycle(%)1 | B |
| Max Wastegate Duty Alternate (RPM) | `` | 2D | WastegateDutyCycle(%) | B |
| Max Wastegate Duty Alternate A (RPM) | `` | 2D | WastegateDutyCycle(%) | B |
| Max Wastegate Duty Alternate B (RPM) | `` | 2D | WastegateDutyCycle(%) | B |
| Max Wastegate Duty Alternate Fix | `` | 1D | MaxWastegateDutyAlternateFix | B |
| Wastegate Duty Ramping Fix | `` | 1D | WastegateDutyRampingFix | B |
| Wastegate Duty Ramping Fix_ | `` | 1D | WastegateDutyRampingFix_ | B |

## Checksum Fix  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Checksum Fix | `` | 1D | ChecksumFix | B |

## Cooling  (3 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Radiator Fan Modes (Veh. Speed) | `d934c` |  |  | R* |
| Radiator Fan Modes A (ECT) | `d932c` |  |  | R* |
| Radiator Fan Modes B (ECT) | `d933c` |  |  | R* |

## Diagnostic Trouble Codes  (233 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| (P000A) CAMSHAFT POSITION A  TIMING SLOW RESPONSE BANK 1 | `` | 1D | PXXXX enable | B |
| (P000B) CAMSHAFT POSITION B  TIMING SLOW RESPONSE BANK 1 | `` | 1D | PXXXX enable | B |
| (P000C) CAMSHAFT POSITION A  TIMING SLOW RESPONSE BANK 2 | `` | 1D | PXXXX enable | B |
| (P000D) CAMSHAFT POSITION B  TIMING SLOW RESPONSE BANK 2 | `` | 1D | PXXXX enable | B |
| (P0010) CAMSHAFT POSITION A ACTUATOR CIRCUIT BANK 1 | `` | 1D | PXXXX enable | B |
| (P0013) CAMSHAFT POSITION B ACTUATOR CIRCUIT  OPEN BANK 1 | `` | 1D | PXXXX enable | B |
| (P0014) EXHAUST AVCS SYSTEM 1 RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0017) CRANK/CAM TIMING B FAILURE 1 | `` | 1D | PXXXX enable | B |
| (P0019) CRANK/CAM TIMING B FAILURE 2 | `` | 1D | PXXXX enable | B |
| (P0020) CAMSHAFT POSITION A ACTUATOR CIRCUIT BANK 2 | `` | 1D | PXXXX enable | B |
| (P0023) CAMSHAFT POSITION B ACTUATOR CIRCUIT  OPEN BANK 2 | `` | 1D | PXXXX enable | B |
| (P0024) EXHAUST AVCS SYSTEM 2 RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0026) OSV SOLENOID VALVE CIRCUIT RANGE/PERF B1 | `` | 1D | PXXXX enable | B |
| (P0028) OSV SOLENOID VALVE CIRCUIT RANGE/PERF B2 | `` | 1D | PXXXX enable | B |
| (P0043) HO2S CIRCUIT LOW B1 S3 | `` | 1D | PXXXX enable | B |
| (P0044) HO2S CIRCUIT HIGH B1 S3 | `` | 1D | PXXXX enable | B |
| (P0050) HO2S CIRCUIT RANGE/PERF B2 S1 | `` | 1D | PXXXX enable | B |
| (P0051) HO2S CIRCUIT LOW B2 S1 | `` | 1D | PXXXX enable | B |
| (P0052) HO2S CIRCUIT HIGH B2 S1 | `` | 1D | PXXXX enable | B |
| (P0057) HO2S CIRCUIT LOW B2 S2 | `` | 1D | PXXXX enable | B |
| (P0058) HO2S CIRCUIT HIGH B2 S2 | `` | 1D | PXXXX enable | B |
| (P0076) INTAKE VALVE CIRCUIT LOW (BANK 1) | `` | 1D | PXXXX enable | B |
| (P0077) INTAKE VALVE CONTROL HIGH (BANK 1) | `` | 1D | PXXXX enable | B |
| (P0082) INTAKE VALVE CONTROL LOW (BANK 2) | `` | 1D | PXXXX enable | B |
| (P0083) INTAKE VALVE CONTROL HIGH (BANK 2) | `` | 1D | PXXXX enable | B |
| (P0087) FUEL RAIL  SYSTEM PRESSURE  TOO LOW | `` | 1D | PXXXX enable | B |
| (P0088) FUEL RAIL  SYSTEM PRESSURE  TOO HIGH | `` | 1D | PXXXX enable | B |
| (P0116) ENGINE COOLANT TEMPERATURE CIRCUIT RANGE  PERFORMANCE PROBLEM | `` | 1D | PXXXX enable | B |
| (P0121) TPS RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0126) INSUFFICIENT COOLANT TEMP (OPERATION) | `` | 1D | PXXXX enable | B |
| (P0129) ATMOS. PRESSURE SENSOR RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0133) FRONT O2 SENSOR SLOW RESPONSE | `` | 1D | PXXXX enable | B |
| (P0139) REAR O2 SENSOR SLOW RESPONSE | `` | 1D | PXXXX enable | B |
| (P013A) OXYGEN SENSOR SLOW RESPONSE  RICH TO LEAN BANK 1 SENSOR 2 | `` | 1D | PXXXX enable | B |
| (P013B) O2 SENSOR SLOW RESPONSE  LEAN TO RICH BANK 1 SENSOR 2 | `` | 1D | PXXXX enable | B |
| (P013E) O2 SENSOR DELAYED RESPONSE  RICH TO LEAN BANK 1 SENSOR 2 | `` | 1D | PXXXX enable | B |
| (P013F) O2 SENSOR DELAYED RESPONSE  LEAN TO RICH BANK 1 SENSOR 2 | `` | 1D | PXXXX enable | B |
| (P0143) O2 SENSOR CIRCUIT LOW B1 S3 | `` | 1D | PXXXX enable | B |
| (P0144) O2 SENSOR CIRCUIT HIGH B1 S3 | `` | 1D | PXXXX enable | B |
| (P0145) O2 SENSOR CIRCUIT SLOW RESPONSE B1 S3 | `` | 1D | PXXXX enable | B |
| (P0151) O2 SENSOR CIRCUIT LOW B2 S1 | `` | 1D | PXXXX enable | B |
| (P0152) O2 SENSOR CIRCUIT HIGH B2 S1 | `` | 1D | PXXXX enable | B |
| (P0153) O2 SENSOR CIRCUIT SLOW RESPONSE B2 S1 | `` | 1D | PXXXX enable | B |
| (P0154) O2 SENSOR CIRCUIT OPEN B2 S1 | `` | 1D | PXXXX enable | B |
| (P0157) O2 SENSOR CIRCUIT LOW B2 S2 | `` | 1D | PXXXX enable | B |
| (P0158) O2 SENSOR CIRCUIT HIGH B2 S2 | `` | 1D | PXXXX enable | B |
| (P0159) O2 SENSOR CIRCUIT SLOW RESPONSE B2 S2 | `` | 1D | PXXXX enable | B |
| (P015B) O2 SENSOR DELAYED RESPONSE RICH TO LEAN B1 S1 | `` | 1D | PXXXX enable | B |
| (P0160) O2 SENSOR NO ACTIVITY B2 S2 | `` | 1D | PXXXX enable | B |
| (P0161) O2 SENSOR HEATER CIRCUIT MALFUNCTION B2 S2 | `` | 1D | PXXXX enable | B |
| (P0174) SYSTEM TOO LEAN B2 | `` | 1D | PXXXX enable | B |
| (P0175) SYSTEM TOO RICH B2 | `` | 1D | PXXXX enable | B |
| (P0181) FUEL TEMP SENSOR A RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0182) FUEL TEMP SENSOR A LOW INPUT | `` | 1D | PXXXX enable | B |
| (P0183) FUEL TEMP SENSOR A HIGH INPUT | `` | 1D | PXXXX enable | B |
| (P0191) FUEL RAIL PRESSURE SENSOR CIRCUIT RANGE  PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P0192) FUEL RAIL PRESSURE SENSOR CIRCUIT LOW INPUT | `` | 1D | PXXXX enable | B |
| (P0193) FUEL RAIL PRESSURE SENSOR CIRCUIT HIGH INPUT | `` | 1D | PXXXX enable | B |
| (P0196) OIL TEMP SENSOR RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0197) OIL TEMP SENSOR LOW | `` | 1D | PXXXX enable | B |
| (P0198) OIL TEMP SENSOR HIGH | `` | 1D | PXXXX enable | B |
| (P0201) INJECTOR CIRCUIT OPEN  CYLINDER 1 | `` | 1D | PXXXX enable | B |
| (P0202) INJECTOR CIRCUIT OPEN  CYLINDER 2 | `` | 1D | PXXXX enable | B |
| (P0203) INJECTOR CIRCUIT OPEN  CYLINDER 3 | `` | 1D | PXXXX enable | B |
| (P0204) INJECTOR CIRCUIT OPEN  CYLINDER 4 | `` | 1D | PXXXX enable | B |
| (P0261) FUEL INJECTOR #1 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0264) FUEL INJECTOR #2 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0267) FUEL INJECTOR #3 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0270) FUEL INJECTOR #4 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0300) RANDOM MULTIPLE CYLINDER MISFIRE DETECTED | `` | 1D | PXXXX enable | B |
| (P0305) MISFIRE CYLINDER 5 | `` | 1D | PXXXX enable | B |
| (P0306) MISFIRE CYLINDER 6 | `` | 1D | PXXXX enable | B |
| (P0332) KNOCK SENSOR 2 LOW INPUT | `` | 1D | PXXXX enable | B |
| (P0333) KNOCK SENSOR 2 HIGH INPUT | `` | 1D | PXXXX enable | B |
| (P0340) CAMSHAFT POS. SENSOR A MALFUNCTION_ | `` | 1D | PXXXX enable | B |
| (P0346) CAMSHAFT POSITION SENSOR A CIRCUIT RANGE  PERFORMANCE BANK 2 | `` | 1D | PXXXX enable | B |
| (P0350) IGNITION COIL PRIMARY/SECONDARY | `` | 1D | PXXXX enable | B |
| (P0351) IGNITION COIL A PRIMARY  SECONDARY CIRCUIT | `` | 1D | PXXXX enable | B |
| (P0352) IGNITION COIL B PRIMARY  SECONDARY CIRCUIT | `` | 1D | PXXXX enable | B |
| (P0353) IGNITION COIL C PRIMARY  SECONDARY CIRCUIT | `` | 1D | PXXXX enable | B |
| (P0354) IGNITION COIL D PRIMARY  SECONDARY CIRCUIT | `` | 1D | PXXXX enable | B |
| (P0365) CAMSHAFT POS. SENSOR B BANK 1 | `` | 1D | PXXXX enable | B |
| (P0365) CAMSHAFT POS. SENSOR B BANK 1_ | `` | 1D | PXXXX enable | B |
| (P0366) CAMSHAFT POSITION SENSOR B CIRCUIT RANGE  PERFORMANCE BANK 1 | `` | 1D | PXXXX enable | B |
| (P0390) CAMSHAFT POS. SENSOR B BANK 2 | `` | 1D | PXXXX enable | B |
| (P0390) CAMSHAFT POS. SENSOR B BANK 2_ | `` | 1D | PXXXX enable | B |
| (P0391) CAMSHAFT POSITION SENSOR B CIRCUIT RANGE  PERFORMANCE BANK 2 | `` | 1D | PXXXX enable | B |
| (P0400) EGR FLOW | `` | 1D | PXXXX enable | B |
| (P0418) SECONDARY AIR PUMP RELAY A | `` | 1D | PXXXX enable | B |
| (P0442) EVAP LEAK DETECTED (SMALL) | `` | 1D | PXXXX enable | B |
| (P0447) EVAP VENT CONTROL CIRCUIT OPEN | `` | 1D | PXXXX enable | B |
| (P0448) EVAP VENT CONTROL CIRCUIT SHORTED | `` | 1D | PXXXX enable | B |
| (P0457) EVAP LEAK DETECTED (FUEL CAP) | `` | 1D | PXXXX enable | B |
| (P0464) FUEL LEVEL SENSOR INTERMITTENT | `` | 1D | PXXXX enable | B |
| (P0483) RADIATOR FAN RATIONALITY CHECK | `` | 1D | PXXXX enable | B |
| (P0502) VEHICLE SPEED SENSOR LOW INPUT | `` | 1D | PXXXX enable | B |
| (P0503) VEHICLE SPEED SENSOR INTERMITTENT | `` | 1D | PXXXX enable | B |
| (P0508) IDLE CONTROL CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0509) IDLE CONTROL CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P050E) | `` | 1D | PXXXX enable | B |
| (P0516) | `` | 1D | PXXXX enable | B |
| (P0517) | `` | 1D | PXXXX enable | B |
| (P0519) IDLE CONTROL MALFUNCTION (FAIL-SAFE) | `` | 1D | PXXXX enable | B |
| (P0545) EGT SENSOR CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0546) EGT SENSOR CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P0558) ALTERNATOR CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0559) ALTERNATOR CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P0560) SYSTEM VOLTAGE | `` | 1D | PXXXX enable | B |
| (P0562) SYSTEM VOLTAGE LOW | `` | 1D | PXXXX enable | B |
| (P0563) SYSTEM VOLTAGE HIGH | `` | 1D | PXXXX enable | B |
| (P0565) CRUISE CONTROL SET SIGNAL | `` | 1D | PXXXX enable | B |
| (P0600) SERIAL COMMUNICATION LINK | `` | 1D | PXXXX enable | B |
| (P0602) CONTROL MODULE PROG. ERROR | `` | 1D | PXXXX enable | B |
| (P0606) ECM  PCM PROCESSOR | `` | 1D | PXXXX enable | B |
| (P0607) CONTROL MODULE PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P060A) | `` | 1D | PXXXX enable | B |
| (P060B) | `` | 1D | PXXXX enable | B |
| (P0616) STARTER RELAY CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0617) STARTER RELAY CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P062D) NO. 1 FUEL INJECTOR DRIVER CIRCUIT PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P062F) | `` | 1D | PXXXX enable | B |
| (P0638) THROTTLE ACTUATOR RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0691) RADIATOR FAN CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0692) RADIATOR FAN CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P0700) TRANSMISSION CONTROL SYSTEM | `` | 1D | PXXXX enable | B |
| (P0703) BRAKE SWITCH INPUT MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P0705) TRANSMISSION RANGE SENSOR MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P0710) ATF TEMP SENSOR MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P0716) TORQUE CONVERTER TURBINE SPEED RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0720) AT VEHICLE SPEED SENSOR HIGH | `` | 1D | PXXXX enable | B |
| (P0726) ENGINE SPEED INPUT RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0731) GEAR 1 INCORRECT RATIO | `` | 1D | PXXXX enable | B |
| (P0732) GEAR 2 INCORRECT RATIO | `` | 1D | PXXXX enable | B |
| (P0733) GEAR 3 INCORRECT RATIO | `` | 1D | PXXXX enable | B |
| (P0734) GEAR 4 INCORRECT RATIO | `` | 1D | PXXXX enable | B |
| (P0741) TORQUE CONVERTER CLUTCH MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P0743) TORQUE CONVERTER CLUTCH LOCK-UP DUTY SOLENOID | `` | 1D | PXXXX enable | B |
| (P0748) PRESSURE CONTROL LINE PRESSURE DUTY SOLENOID | `` | 1D | PXXXX enable | B |
| (P0753) SHIFT SOLENOID A ELECTRICAL | `` | 1D | PXXXX enable | B |
| (P0758) SHIFT SOLENOID B ELECTRICAL | `` | 1D | PXXXX enable | B |
| (P0771) AT LOW CLUTCH TIMING SOLENOID MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P0778) AT 2-4 BRAKE PRESSURE SOLENOID MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P0785) AT 2-4 BRAKE TIMING SOLENOID MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P081A) | `` | 1D | PXXXX enable | B |
| (P0864) TCM COMMUNICATION RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P0865) TCM COMMUNICATION CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P0866) TCM COMMUNICATION CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P1026) VVL SYSTEMS 1 PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P1028) VVL SYSTEMS 2 PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P1086) TGV POS. 2 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P1087) TGV POS. 2 CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P1088) TGV POS. 1 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P1089) TGV POS. 1 CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P1090) TGV SYSTEM 1 (VALVE OPEN) | `` | 1D | PXXXX enable | B |
| (P1091) TGV SYSTEM 1 (VALVE CLOSE) | `` | 1D | PXXXX enable | B |
| (P1092) TGV SYSTEM 2 (VALVE OPEN) | `` | 1D | PXXXX enable | B |
| (P1093) TGV SYSTEM 2 (VALVE CLOSE) | `` | 1D | PXXXX enable | B |
| (P1094) TGV SIGNAL 1 (OPEN) | `` | 1D | PXXXX enable | B |
| (P1095) TGV SIGNAL 1 (SHORT) | `` | 1D | PXXXX enable | B |
| (P1096) TGV SIGNAL 2 (OPEN) | `` | 1D | PXXXX enable | B |
| (P1097) TGV SIGNAL 2 (SHORT) | `` | 1D | PXXXX enable | B |
| (P1109) THROTTLE DEPOSIT MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P1110) ATMOS. PRESSURE SENSOR LOW INPUT | `` | 1D | PXXXX enable | B |
| (P1111) ATMOS. PRESSURE SENSOR HIGH INPUT | `` | 1D | PXXXX enable | B |
| (P1152) FRONT O2 SENSOR RANGE/PERF LOW B1 S1 | `` | 1D | PXXXX enable | B |
| (P1153) FRONT O2 SENSOR RANGE/PERF HIGH B1 S1 | `` | 1D | PXXXX enable | B |
| (P1154) O2 SENSOR RANGE/PERF LOW B2 S1 | `` | 1D | PXXXX enable | B |
| (P1155) O2 SENSOR RANGE/PERF HIGH B2 S1 | `` | 1D | PXXXX enable | B |
| (P1170) PORT INJECTOR FUEL PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P117B) DIRECT INJECTOR FUEL PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P119E) | `` | 1D | PXXXX enable | B |
| (P119F) | `` | 1D | PXXXX enable | B |
| (P1235) HIGH PRESSURE FUEL PUMP CIRCUIT | `` | 1D | PXXXX enable | B |
| (P1261) DI INJECTOR CIRCUIT  OPEN  CYLINDER 1 | `` | 1D | PXXXX enable | B |
| (P1262) DI INJECTOR CIRCUIT  OPEN  CYLINDER 2 | `` | 1D | PXXXX enable | B |
| (P1263) DI INJECTOR CIRCUIT  OPEN  CYLINDER 3 | `` | 1D | PXXXX enable | B |
| (P1264) DI INJECTOR CIRCUIT  OPEN  CYLINDER 4 | `` | 1D | PXXXX enable | B |
| (P1282) PCV SYSTEM CIRCUIT (OPEN) | `` | 1D | PXXXX enable | B |
| (P1301) MISFIRE (HIGH TEMP EXHAUST GAS) | `` | 1D | PXXXX enable | B |
| (P1312) EGT SENSOR MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P1418) SECONDARY AIR PUMP CIRCUIT SHORTED | `` | 1D | PXXXX enable | B |
| (P1443) VENT CONTROL SOLENOID FUNCTION PROBLEM | `` | 1D | PXXXX enable | B |
| (P1446) FUEL TANK SENSOR CONTROL CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P1447) FUEL TANK SENSOR CONTROL CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P1448) FUEL TANK SENSOR CONTROL RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P1458) CANISTER PURGE CONTROL SOLENOID VALVE 2 LOW | `` | 1D | PXXXX enable | B |
| (P1459) CANISTER PURGE CONTROL SOLENOID VALVE 2 HIGH | `` | 1D | PXXXX enable | B |
| (P1491) PCV (BLOWBY) FUNCTION PROBLEM | `` | 1D | PXXXX enable | B |
| (P1492) EGR SOLENOID SIGNAL 1 MALFUNCTION (LOW) | `` | 1D | PXXXX enable | B |
| (P1493) EGR SOLENOID SIGNAL 1 MALFUNCTION (HIGH) | `` | 1D | PXXXX enable | B |
| (P1494) EGR SOLENOID SIGNAL 2 MALFUNCTION (LOW) | `` | 1D | PXXXX enable | B |
| (P1495) EGR SOLENOID SIGNAL 2 MALFUNCTION (HIGH) | `` | 1D | PXXXX enable | B |
| (P1496) EGR SIGNAL 3 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P1497) EGR SOLENOID SIGNAL 3 MALFUNCTION (HIGH) | `` | 1D | PXXXX enable | B |
| (P1498) EGR SIGNAL 4 CIRCUIT LOW | `` | 1D | PXXXX enable | B |
| (P1499) EGR SIGNAL 4 CIRCUIT HIGH | `` | 1D | PXXXX enable | B |
| (P1518) STARTER SWITCH LOW INPUT | `` | 1D | PXXXX enable | B |
| (P1519) IMRC STUCK CLOSED | `` | 1D | PXXXX enable | B |
| (P1520) IMRC CIRCUIT MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P1530) BATTERY CURRENT SENSOR CIRCUIT (LOW) | `` | 1D | PXXXX enable | B |
| (P1531) BATTERY CURRENT SENSOR CIRCUIT (HIGH) | `` | 1D | PXXXX enable | B |
| (P1532) CHARGING CONTROL SYSTEM | `` | 1D | PXXXX enable | B |
| (P1544) EGT TOO HIGH | `` | 1D | PXXXX enable | B |
| (P1560) BACK-UP VOLTAGE MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P1602) CONTROL MODULE PROGRAMMING ERROR | `` | 1D | PXXXX enable | B |
| (P1603) ENGINE STALL HISTORY | `` | 1D | PXXXX enable | B |
| (P1604) STARTABILITY MALFUNCTION | `` | 1D | PXXXX enable | B |
| (P1616) SBDS INTERACTIVE CODES | `` | 1D | PXXXX enable | B |
| (P1700) TPS CIRCUIT MALFUNCTION (AT) | `` | 1D | PXXXX enable | B |
| (P2090) OCV SOLENOID B1 CIRCUIT OPEN | `` | 1D | PXXXX enable | B |
| (P2091) OCV SOLENOID B1 CIRCUIT SHORT | `` | 1D | PXXXX enable | B |
| (P2094) OCV SOLENOID B2 CIRCUIT OPEN | `` | 1D | PXXXX enable | B |
| (P2095) OCV SOLENOID B2 CIRCUIT SHORT | `` | 1D | PXXXX enable | B |
| (P2098) POST CATALYST TOO LEAN B2 | `` | 1D | PXXXX enable | B |
| (P2099) POST CATALYST TOO RICH B2 | `` | 1D | PXXXX enable | B |
| (P2119) THROTTLE ACTUATOR CONTROL THROTTLE BODY RANGE  PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P2195) OXYGEN AF SENSOR SIGNAL STUCK LEAN BANK 1 SENSOR 1 | `` | 1D | PXXXX enable | B |
| (P2196) OXYGEN AF SENSOR SIGNAL STUCK RICH BANK 1 SENSOR 1 | `` | 1D | PXXXX enable | B |
| (P219B) BANK 2 AFR IMBALANCE | `` | 1D | PXXXX enable | B |
| (P2227) BARO. PRESSURE CIRCUIT RANGE/PERF | `` | 1D | PXXXX enable | B |
| (P2228) BARO. PRESSURE CIRCUIT LOW INPUT | `` | 1D | PXXXX enable | B |
| (P2229) BARO. PRESSURE CIRCUIT HIGH INPUT | `` | 1D | PXXXX enable | B |
| (P2404) EVAP LEAK DETECTION PUMP SENSE CIRCUIT RANGE PERF | `` | 1D | PXXXX enable | B |
| (P2503) CHARGING SYSTEM VOLTAGE LOW | `` | 1D | PXXXX enable | B |
| (P2504) CHARGING SYSTEM VOLTAGE HIGH | `` | 1D | PXXXX enable | B |
| (P2610) ECM PCM INTERNAL ENGINE OFF TIMER PERFORMANCE | `` | 1D | PXXXX enable | B |
| (P9571) | `` | 1D | PXXXX enable | B |
| (P9572) | `` | 1D | PXXXX enable | B |
| (P9576) | `` | 1D | PXXXX enable | B |
| (P9577) | `` | 1D | PXXXX enable | B |
| (P9578) | `` | 1D | PXXXX enable | B |
| (U0155) LOST COMMUNICATION WITH INSTRUMENT PANEL CLUSTER (IPC) CONTROL MODULE | `` | 1D | PXXXX enable | B |
| (U0423) INVALID DATA RECEIVED FROM INSTRUMENT PANEL CLUSTER CONTROL MODULE | `` | 1D | PXXXX enable | B |

## Diagnostics / DTC  (152 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| (P0000) PASS CODE (NO DTC DETECTED) | `9a797` |  |  | R* |
| (P0000) PASS CODE (NO DTC DETECTED)_ | `9a798` |  |  | R* |
| (P0011) CAMSHAFT POS. - TIMING OVER-ADVANCED 1 | `9a784` |  |  | R* |
| (P0016) CRANKSHAFT/CAMSHAFT CORRELATION 1A | `9a7e5` |  |  | R* |
| (P0018) CRANKSHAFT/CAMSHAFT CORRELATION 2A | `9a7e4` |  |  | R* |
| (P0021) CAMSHAFT POS. - TIMING OVER-ADVANCED 2 | `9a785` |  |  | R* |
| (P0030) FRONT O2 SENSOR RANGE/PERF | `9a7ae` |  |  | R* |
| (P0031) FRONT O2 SENSOR LOW INPUT | `9a7a3` |  |  | R* |
| (P0032) FRONT O2 SENSOR HIGH INPUT | `9a7a1` |  |  | R* |
| (P0037) REAR O2 SENSOR LOW INPUT | `9a7a2` |  |  | R* |
| (P0038) REAR O2 SENSOR HIGH INPUT | `9a7a0` |  |  | R* |
| (P0068) MAP SENSOR RANGE/PERF | `9a7ab` |  |  | R* |
| (P0101) MAF SENSOR RANGE/PERF | `9a7ac` |  |  | R* |
| (P0102) MAF SENSOR LOW INPUT | `9a773` |  |  | R* |
| (P0103) MAF SENSOR HIGH INPUT | `9a774` |  |  | R* |
| (P0107) MAP SENSOR LOW INPUT | `9a7a4` |  |  | R* |
| (P0108) MAP SENSOR HIGH INPUT | `9a7a5` |  |  | R* |
| (P0111) IAT SENSOR RANGE/PERF | `9a79f` |  |  | R* |
| (P0112) IAT SENSOR LOW INPUT | `9a79d` |  |  | R* |
| (P0113) IAT SENSOR HIGH INPUT | `9a79e` |  |  | R* |
| (P0117) COOLANT TEMP SENSOR LOW INPUT | `9a77a` |  |  | R* |
| (P0118) COOLANT TEMP SENSOR HIGH INPUT | `9a77b` |  |  | R* |
| (P0122) TPS A LOW INPUT | `9a778` |  |  | R* |
| (P0123) TPS A HIGH INPUT | `9a779` |  |  | R* |
| (P0125) INSUFFICIENT COOLANT TEMP (FUELING) | `9a77c` |  |  | R* |
| (P0128) THERMOSTAT MALFUNCTION | `9a7a6` |  |  | R* |
| (P0131) FRONT O2 SENSOR LOW INPUT | `9a79a` |  |  | R* |
| (P0132) FRONT O2 SENSOR HIGH INPUT | `9a79b` |  |  | R* |
| (P0134) FRONT O2 SENSOR NO ACTIVITY | `9a7ad` |  |  | R* |
| (P0137) REAR O2 SENSOR LOW VOLTAGE | `9a799` |  |  | R* |
| (P0138) REAR O2 SENSOR HIGH VOLTAGE | `9a79c` |  |  | R* |
| (P013A) O2 SENSOR SLOW RESPONSE RICH TO LEAN B1 S2 | `9a815` |  |  | R* |
| (P013B) O2 SENSOR SLOW RESPONSE LEAN TO RICH B1 S2 | `9a814` |  |  | R* |
| (P013E) O2 SENSOR DELAYED RESPONSE RICH TO LEAN B1 S2 | `9a813` |  |  | R* |
| (P013F) O2 SENSOR DELAYED RESPONSE LEAN TO RICH B1 S2 | `9a812` |  |  | R* |
| (P0140) REAR O2 SENSOR NO ACTIVITY | `9a7e2` |  |  | R* |
| (P0141) REAR O2 SENSOR MALFUNCTION | `9a78a` |  |  | R* |
| (P014C) O2 SENSOR SLOW RESPONSE RICH TO LEAN B1 S1 | `9a808` |  |  | R* |
| (P014D) O2 SENSOR SLOW RESPONSE LEAN TO RICH B1 S1 | `9a807` |  |  | R* |
| (P015A) O2 SENSOR DELAYED RESPONSE RICH TO LEAN B1 S1 | `9a806` |  |  | R* |
| (P015B) O2 SENSOR DELAYED RESPONSE LEAN TO RICH B1 S1 | `9a805` |  |  | R* |
| (P0171) SYSTEM TOO LEAN | `9a78f` |  |  | R* |
| (P0172) SYSTEM TOO RICH | `9a790` |  |  | R* |
| (P0201) INJECTOR CIRCUIT MALFUNCTION CYLINDER 1 | `9a7f2` |  |  | R* |
| (P0202) INJECTOR CIRCUIT MALFUNCTION CYLINDER 2 | `9a7f5` |  |  | R* |
| (P0203) INJECTOR CIRCUIT MALFUNCTION CYLINDER 3 | `9a7f4` |  |  | R* |
| (P0204) INJECTOR CIRCUIT MALFUNCTION CYLINDER 4 | `9a7f3` |  |  | R* |
| (P0222) TPS B LOW INPUT | `9a7b0` |  |  | R* |
| (P0223) TPS B HIGH INPUT | `9a7b1` |  |  | R* |
| (P0230) FUEL PUMP PRIMARY CIRCUIT | `9a7aa` |  |  | R* |
| (P0244) WASTEGATE SOLENOID A RANGE/PERF | `9a7a9` |  |  | R* |
| (P0245) WASTEGATE SOLENOID A LOW | `9a7a7` |  |  | R* |
| (P0246) WASTEGATE SOLENOID A HIGH | `9a7a8` |  |  | R* |
| (P0301) MISFIRE CYLINDER 1 | `9a791` |  |  | R* |
| (P0302) MISFIRE CYLINDER 2 | `9a792` |  |  | R* |
| (P0303) MISFIRE CYLINDER 3 | `9a793` |  |  | R* |
| (P0304) MISFIRE CYLINDER 4 | `9a794` |  |  | R* |
| (P0327) KNOCK SENSOR 1 LOW INPUT | `9a776` |  |  | R* |
| (P0328) KNOCK SENSOR 1 HIGH INPUT | `9a777` |  |  | R* |
| (P0335) CRANKSHAFT POS. SENSOR A MALFUNCTION | `9a770` |  |  | R* |
| (P0336) CRANKSHAFT POS. SENSOR A RANGE/PERF | `9a771` |  |  | R* |
| (P0340) CAMSHAFT POS. SENSOR A MALFUNCTION | `9a7c1` |  |  | R* |
| (P0341) CAMSHAFT POS. SENSOR A RANGE/PERF | `9a82b` |  |  | R* |
| (P0345) CAMSHAFT POS. SENSOR A BANK 2 | `9a7c0` |  |  | R* |
| (P0351) IGNITION COIL A PRIMARY/SECONDARY CIRCUIT MALFUNCTION | `9a819` |  |  | R* |
| (P0352) IGNITION COIL B PRIMARY/SECONDARY CIRCUIT MALFUNCTION | `9a818` |  |  | R* |
| (P0353) IGNITION COIL C PRIMARY/SECONDARY CIRCUIT MALFUNCTION | `9a817` |  |  | R* |
| (P0354) IGNITION COIL D PRIMARY/SECONDARY CIRCUIT MALFUNCTION | `9a816` |  |  | R* |
| (P0410) SECONDARY AIR PUMP SYSTEM | `9a7dd` |  |  | R* |
| (P0411) SECONDARY AIR PUMP INCORRECT FLOW | `9a7dc` |  |  | R* |
| (P0413) SECONDARY AIR PUMP A OPEN | `9a7e1` |  |  | R* |
| (P0414) SECONDARY AIR PUMP A SHORTED | `9a7e3` |  |  | R* |
| (P0416) SECONDARY AIR PUMP B OPEN | `9a7ec` |  |  | R* |
| (P0417) SECONDARY AIR PUMP B SHORTED | `9a7eb` |  |  | R* |
| (P0420) CAT EFFICIENCY BELOW THRESHOLD | `9a78d` |  |  | R* |
| (P0441) EVAP INCORRECT PURGE FLOW | `9a80d` |  |  | R* |
| (P0451) EVAP PRESSURE SENSOR RANGE/PERF | `9a80c` |  |  | R* |
| (P0452) EVAP PRESSURE SENSOR LOW INPUT | `9a804` |  |  | R* |
| (P0453) EVAP PRESSURE SENSOR HIGH INPUT | `9a803` |  |  | R* |
| (P0455) EVAP EMISSION CONTROL SYSTEM LEAK DETECTED (GROSS LEAK) | `9a80b` |  |  | R* |
| (P0456) EVAP LEAK DETECTED (VERY SMALL) | `9a78e` |  |  | R* |
| (P0458) EVAP PURGE VALVE CIRCUIT LOW | `9a788` |  |  | R* |
| (P0459) EVAP PURGE VALVE CIRCUIT HIGH | `9a789` |  |  | R* |
| (P0461) FUEL LEVEL SENSOR RANGE/PERF | `9a77f` |  |  | R* |
| (P0462) FUEL LEVEL SENSOR LOW INPUT | `9a77d` |  |  | R* |
| (P0463) FUEL LEVEL SENSOR HIGH INPUT | `9a77e` |  |  | R* |
| (P0500) VEHICLE SPEED SENSOR A | `9a775` |  |  | R* |
| (P0506) IDLE CONTROL RPM LOWER THAN EXPECTED | `9a782` |  |  | R* |
| (P0507) IDLE CONTROL RPM HIGH THAN EXPECTED | `9a783` |  |  | R* |
| (P050A) COLD START IDLE AIR CONTROL SYSTEM PERFORMANCE | `9a7fe` |  |  | R* |
| (P050B) COLD START IGNITION TIMING PERFORMANCE | `9a7fd` |  |  | R* |
| (P0512) STARTER REQUEST CIRCUIT | `9a81a` |  |  | R* |
| (P0604) CONTROL MODULE RAM ERROR | `9a772` |  |  | R* |
| (P0605) CONTROL MODULE ROM ERROR | `9a7c2` |  |  | R* |
| (P0851) NEUTRAL SWITCH INPUT LOW | `9a780` |  |  | R* |
| (P0852) NEUTRAL SWITCH INPUT HIGH | `9a781` |  |  | R* |
| (P1160) ABNORMAL RETURN SPRING | `9a7b2` |  |  | R* |
| (P1400) FUEL TANK PRESSURE SOL. LOW | `9a786` |  |  | R* |
| (P1410) SECONDARY AIR PUMP VALVE STUCK OPEN | `9a7e6` |  |  | R* |
| (P1420) FUEL TANK PRESSURE SOL. HIGH INPUT | `9a787` |  |  | R* |
| (P1449) EVAPORATIVE EMISSION CONT. SYS. AIR FILTER CLOG | `9a80a` |  |  | R* |
| (P1451) EVAPORATIVE EMISSION CONT. SYS. | `9a809` |  |  | R* |
| (P2004) TGV - INTAKE MANIFOLD RUNNER 1 STUCK OPEN | `9a7ce` |  |  | R* |
| (P2005) TGV - INTAKE MANIFOLD RUNNER 2 STUCK OPEN | `9a7d0` |  |  | R* |
| (P2006) TGV - INTAKE MANIFOLD RUNNER 1 STUCK CLOSED | `9a7cf` |  |  | R* |
| (P2007) TGV - INTAKE MANIFOLD RUNNER 2 STUCK CLOSED | `9a7d1` |  |  | R* |
| (P2008) TGV - INTAKE MANIFOLD RUNNER 1 CIRCUIT OPEN | `9a7d9` |  |  | R* |
| (P2009) TGV - INTAKE MANIFOLD RUNNER 1 CIRCUIT LOW | `9a7d7` |  |  | R* |
| (P2011) TGV - INTAKE MANIFOLD RUNNER 2 CIRCUIT OPEN | `9a7da` |  |  | R* |
| (P2012) TGV - INTAKE MANIFOLD RUNNER 2 CIRCUIT LOW | `9a7d8` |  |  | R* |
| (P2016) TGV - INTAKE MANIFOLD RUNNER 1 POS. SENSOR LOW | `9a7d3` |  |  | R* |
| (P2017) TGV - INTAKE MANIFOLD RUNNER 1 POS. SENSOR HIGH | `9a7d4` |  |  | R* |
| (P2021) TGV - INTAKE MANIFOLD RUNNER 2 POS. SENSOR LOW | `9a7d5` |  |  | R* |
| (P2022) TGV - INTAKE MANIFOLD RUNNER 2 POS. SENSOR HIGH | `9a7d6` |  |  | R* |
| (P2088) OCV SOLENOID A1 CIRCUIT OPEN | `9a7ca` |  |  | R* |
| (P2089) OCV SOLENOID A1 CIRCUIT SHORT | `9a7c9` |  |  | R* |
| (P2092) OCV SOLENOID A2 CIRCUIT OPEN | `9a7c8` |  |  | R* |
| (P2093) OCV SOLENOID A2 CIRCUIT SHORT | `9a7c7` |  |  | R* |
| (P2096) POST CATALYST TOO LEAN B1 | `9a7b6` |  |  | R* |
| (P2097) POST CATALYST TOO RICH B1 | `9a7bd` |  |  | R* |
| (P2101) THROTTLE ACTUATOR CIRCUIT RANGE/PERF | `9a7b5` |  |  | R* |
| (P2102) THROTTLE ACTUATOR CIRCUIT LOW | `9a7b3` |  |  | R* |
| (P2103) THROTTLE ACTUATOR CIRCUIT HIGH | `9a7b4` |  |  | R* |
| (P2109) TPS A MINIMUM STOP PERF | `9a7af` |  |  | R* |
| (P2122) TPS D CIRCUIT LOW INPUT | `9a7ba` |  |  | R* |
| (P2123) TPS D CIRCUIT HIGH INPUT | `9a7bb` |  |  | R* |
| (P2127) TPS E CIRCUIT LOW INPUT | `9a7b8` |  |  | R* |
| (P2128) TPS E CIRCUIT HIGH INPUT | `9a7b9` |  |  | R* |
| (P2135) TPS A/B VOLTAGE | `9a7bc` |  |  | R* |
| (P2138) TPS D/E VOLTAGE | `9a7b7` |  |  | R* |
| (P219A) BANK 1 AFR IMBALANCE | `9a80f` |  |  | R* |
| (P2401) EVAP LEAK DETECTION PUMP CONTROL CIRCUIT LOW | `9a802` |  |  | R* |
| (P2402) EVAP LEAK DETECTION PUMP CONTROL CIRCUIT HIGH | `9a811` |  |  | R* |
| (P2404) EVAP LEAK DETECTION PUMP SENSE CIRCUIT RANGE/PERF | `9a810` |  |  | R* |
| (P2419) EVAP SWITCHING VALVE LOW | `9a801` |  |  | R* |
| (P2420) EVAP SWITCHING VALVE HIGH | `9a800` |  |  | R* |
| (P2431) SECONDARY AIR PUMP CIRCUIT RANGE/PERF | `9a7de` |  |  | R* |
| (P2432) SECONDARY AIR PUMP CIRCUIT LOW | `9a7e0` |  |  | R* |
| (P2433) SECONDARY AIR PUMP CIRCUIT HIGH | `9a7df` |  |  | R* |
| (P2440) SECONDARY AIR PUMP VALVE 1 STUCK OPEN | `9a7ea` |  |  | R* |
| (P2441) SECONDARY AIR PUMP VALVE 1 STUCK CLOSED | `9a7e9` |  |  | R* |
| (P2442) SECONDARY AIR PUMP VALVE 2 STUCK OPEN | `9a7e8` |  |  | R* |
| (P2443) SECONDARY AIR PUMP 2 STUCK CLOSED | `9a7e7` |  |  | R* |
| (P2444) SECONDARY AIR PUMP 1 STUCK ON B1 | `9a7db` |  |  | R* |
| (P2610) ECM/PCM INTERNAL ENGINE OFF TIMER PERFORMANCE | `9a7ff` |  |  | R* |
| (U0073) CAN COMMUNICATION BUS A OFF | `9a7fc` |  |  | R* |
| (U0101) CAN LOST COMMUNICATION WITH TCM | `9a7f9` |  |  | R* |
| (U0122) CAN LOST COMMUNICATION WITH VDC | `9a7fb` |  |  | R* |
| (U0140) CAN LOST COMMUNICATION WITH BIU | `9a7f7` |  |  | R* |
| (U0402) CAN INVALID DATA RECEIVED FROM TCM | `9a7f8` |  |  | R* |
| (U0416) CAN INVALID DATA RECEIVED FROM VDC | `9a7fa` |  |  | R* |
| (U0422) CAN INVALID DATA RECEIVED FROM BIU | `9a7f6` |  |  | R* |

## Drive-by-Wire Throttle (DBW)  (29 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Requested Torque (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque (Accelerator Pedal)_ | `` | 3D | RequestedTorque(rawecuvalue)1 | B |
| Requested Torque A (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque A (Accelerator Pedal) SI-DRIVE Intelligent | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque A (Accelerator Pedal) SI-DRIVE Sport | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque A (Accelerator Pedal) SI-DRIVE Sport Sharp | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque B (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque B (Accelerator Pedal) SI-DRIVE Intelligent | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque B (Accelerator Pedal) SI-DRIVE Sport | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque B (Accelerator Pedal) SI-DRIVE Sport Sharp | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque Base (RPM)_ | `` | 2D | RequestedTorque(rawecuvalue)1 | B |
| Requested Torque C (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque D (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque E (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Requested Torque F (Accelerator Pedal) | `` | 3D | RequestedTorque(rawecuvalue) | B |
| Target Throttle Plate Position (Idle) | `` | 2D | ThrottlePlateOpeningAngle(%)2 | B |
| Target Throttle Plate Position (Idle) Minimum | `` | 2D | ThrottlePlateOpeningAngle(%)2 | B |
| Target Throttle Plate Position (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position (Requested Torque)_ | `` | 3D | TargetThrottlePlateOpeningAngle(%)1 | B |
| Target Throttle Plate Position A (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position B (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position C (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position Cruise (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position D (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position E (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position F (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position G (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position Maximum (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |
| Target Throttle Plate Position Non-Cruise (Requested Torque) | `` | 3D | TargetThrottlePlateOpeningAngle(%) | B |

## Fuel  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Info Panel Fuel Consumption Correction | `` | 2D | rawecuvalue | B |

## Fuel System  (7 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Cluster Display Fuel Consumption Correction | `c1598` |  |  | R* |
| Fuel Pump Duty High (Running) | `4bbac` | 1D | rawecuvalueverbose | R |
| Fuel Pump Duty Low (Idle/Steady) | `4bbb0` | 1D | rawecuvalueverbose | R |
| Fuel Pump Duty Max (Prime/Cranking) | `4bba0` | 1D | rawecuvalueverbose | R |
| Fuel Pump Min Voltage Threshold | `4bbf0` | 1D | rawecuvalueverbose | R |
| Fuel Pump Run Time Gate A | `d6018` | 1D | MapSwitchCounter | R |
| Fuel Pump Run Time Gate B | `d601a` | 1D | MapSwitchCounter | R |

## Fueling - AF Correction / Learning  (8 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| A/F Learning #1 Limits | `cc064` |  |  | R* |
| A/F Learning #1/#2 Limits | `` | 2D | A/FLearning#1and#2Limits(%) | B |
| A/F Learning Airflow Ranges | `` | 2D | MassAirflow(g/s)1 | B |
| A/F Learning Max Limit (ECT) | `` | 2D | A/FLearning#1and#2Max(%) | B |
| A/F Learning Min Limit (ECT) | `` | 2D | A/FLearning#1and#2Min(%) | B |
| AF 3 Correction Adder (Decrease) | `` | 2D |  | R |
| AF 3 Correction Adder (Increase) B | `` | 2D | AF3_Adder2 | R |
| AF 3 Correction Limits | `35ffc` | 2D | A/FLearning#1Limits(%) | R |

## Fueling - Base / Enrichment  (45 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Cranking Fuel IPW Compensation (Accelerator) | `cc89c` |  |  | R* |
| Cranking Fuel IPW Compensation (IAT) | `cc8bc` |  |  | R* |
| Cranking Fuel IPW Compensation (MAP) | `cc868` |  |  | R* |
| Cranking Fuel IPW Compensation Imm. Cruise (RPM) | `cf704` |  |  | R* |
| Cranking Fuel IPW Compensation Imm. Non-Cruise (RPM) | `cf6b0` |  |  | R* |
| Front Oxygen Sensor Compensation (Atm. Pressure) | `c3708` |  |  | R* |
| Front Oxygen Sensor Rich Limit | `21cac` |  |  | R* |
| Front Oxygen Sensor Scaling | `d8da8` |  |  | R* |
| Min Primary Base Enrichment 1 (Non-Primary OL)_ | `cc830` |  |  | R* |
| Min Primary Base Enrichment 1 Cruise | `cf95c` |  |  | R* |
| Min Primary Base Enrichment 1 Non-Cruise | `cf8b8` |  |  | R* |
| Minimum Tip-in Enrichment Activation | `cc4a4` |  |  | R* |
| Minimum Tip-in Enrichment Activation (Throttle) | `cc4a0` |  |  | R* |
| Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_1A | `CD446` |  |  | R* |
| Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_1B | `CD4A6` |  |  | R* |
| Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_2A | `CD4E6` |  |  | R* |
| Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_2B | `CD546` |  |  | R* |
| Table_Post_Start_Enrich_High_Speed_Decay_Step_Value_1 | `CD5A6` |  |  | R* |
| Table_Post_Start_Enrich_High_Speed_Decay_Step_Value_2 | `CD5E6` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Delay_1 | `CD426` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Delay_2 | `CD586` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Delay_Multiplier | `CD666` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Initial_1A | `CD3A6` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Initial_1B | `CD3C6` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Initial_2A | `CD3E6` |  |  | R* |
| Table_Post_Start_Enrich_Low_Speed_Decay_Initial_2B | `CD406` |  |  | R* |
| Tau Input A Falling Load Activation | `cd746` |  |  | R* |
| Tau Input A Falling Load Activation A | `cd766` |  |  | R* |
| Tau Input A Falling Load Activation B | `cd848` |  |  | R* |
| Tau Input A Falling Load Activation C | `cd868` |  |  | R* |
| Tau Input A Rising Load Activation | `cd6e6` |  |  | R* |
| Throttle Tip-in Enrichment A | `ced50` |  |  | R* |
| Throttle Tip-in Enrichment B | `cedbc` |  |  | R* |
| Tip-in Enrichment Applied Counter Reset | `cbc08` |  |  | R* |
| Tip-in Enrichment Compensation (RPM) | `cd118` |  |  | R* |
| Tip-in Enrichment Compensation A (ECT) | `cd155` |  |  | R* |
| Tip-in Enrichment Compensation B (ECT) | `cede0` |  |  | R* |
| Tip-in Enrichment Compensation C (ECT) | `cee00` |  |  | R* |
| Tip-in Enrichment Compensation D (ECT) | `cee40` |  |  | R* |
| Tip-in Enrichment Compensation D (ECT) Activation | `cc4a8` |  |  | R* |
| Tip-in Enrichment Disable Applied Counter Threshold A (ECT) | `cd165` |  |  | R* |
| Tip-in Enrichment Disable Applied Counter Threshold B (ECT) | `cd175` |  |  | R* |
| Tip-in Enrichment Disable Throttle Cumulative Threshold A (ECT) | `cee60` |  |  | R* |
| Tip-in Enrichment Disable Throttle Cumulative Threshold B (ECT) | `cee80` |  |  | R* |
| Tip-in Throttle Cumulative Reset | `cbc09` |  |  | R* |

## Fueling - CL/OL Transition  (51 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| CL Delay Engine Load Counter Threshold | `cbc5a` |  |  | R* |
| CL Delay Engine Speed B Counter Threshold | `` | 2D | counterthreshold1 | B |
| CL Delay Maximum (EGT) | `` | 2D | DegreesF | B |
| CL Delay Maximum (Engine Load) | `cc204` |  |  | R* |
| CL Delay Maximum (Throttle) | `cc1d8` |  |  | R* |
| CL Delay Maximum (Throttle) (High Atm. Pressure) | `` | 2D | ThrottlePlateOpeningAngle(%) | B |
| CL Delay Maximum (Throttle) (Low Atm. Pressure) | `` | 2D | ThrottlePlateOpeningAngle(%) | B |
| CL Delay Maximum (Throttle) A | `` | 2D | AcceleratorPedalAngle(%)1 | B |
| CL Delay Maximum (Throttle) B (ECT) | `` | 2D | AcceleratorPedalAngle(%) | B |
| CL Delay Maximum (Vehicle Speed) | `cc1f4` |  |  | R* |
| CL Delay Maximum Engine Speed (Neutral) | `cc1a8` |  |  | R* |
| CL Delay Maximum Engine Speed (Per Gear) | `cc180` |  |  | R* |
| CL Delay Maximum Engine Speed (Per Gear)(AT) | `` | 2D | EngineSpeed(RPM)1 | B |
| CL Delay Maximum Engine Speed (Per Gear)(MT) | `` | 2D | EngineSpeed(RPM)1 | B |
| CL Delay Maximum Engine Speed A | `` | 2D | EngineSpeed(RPM)1 | B |
| CL Delay Maximum Engine Speed B | `` | 2D | EngineSpeed(RPM)1 | B |
| CL Delay Minimum (ECT) | `cc17c` |  |  | R* |
| CL Delay Throttle A Counter Threshold | `` | 2D | counterthreshold1 | B |
| CL Delay Throttle Atm. Pressure Thresholds | `` | 2D | AtmosphericPressure(psi) | B |
| CL Fueling Target Compensation (ECT) Disable | `cbf9c` |  |  | R* |
| CL Fueling Target Compensation A (Load) | `d14d0` |  |  | R* |
| CL Fueling Target Compensation B (Load) | `d1740` |  |  | R* |
| CL Fueling Target Compensation Imm. Cruise (ECT) | `d13b0` |  |  | R* |
| CL Fueling Target Compensation Imm. Non-Cruise (ECT) | `d141c` |  |  | R* |
| CL to OL Delay | `` | 2D | counterthreshold1 | B |
| CL to OL Delay (Atm. Pressure) | `` | 2D | counterthreshold1 | B |
| CL to OL Delay A (Atm. Pressure) | `` | 2D | counterthreshold1 | B |
| CL to OL Delay B (Atm. Pressure) | `` | 2D | counterthreshold1 | B |
| CL to OL Delay/Switch SI-DRIVE Intelligent | `cbc5c` |  |  | R* |
| CL to OL Delay_ | `cbc62` |  |  | R* |
| CL to OL Transition with Delay (Accelerator) | `` | 2D | AcceleratorPedalAngle(%) | B |
| CL to OL Transition with Delay (Throttle) | `ccd78` |  |  | R* |
| CL to OL Transition with Delay A (Base Pulse Width) | `` | 2D | BasePulseWidth(ms)1 | B |
| CL to OL Transition with Delay A (Throttle) | `` | 2D | ThrottlePlateOpeningAngle(%)1 | B |
| CL to OL Transition with Delay B (Base Pulse Width) | `` | 2D | BasePulseWidth(ms)1 | B |
| CL to OL Transition with Delay B (Throttle) | `` | 2D | ThrottlePlateOpeningAngle(%)1 | B |
| CL to OL Transition with Delay BPW Hysteresis | `cc174` |  |  | R* |
| CL to OL Transition with Delay C (Base Pulse Width) | `` | 2D | BasePulseWidth(ms)1 | B |
| CL to OL Transition with Delay C (Throttle) | `` | 2D | ThrottlePlateOpeningAngle(%)1 | B |
| CL to OL Transition with Delay Throttle Hysteresis | `cc178` |  |  | R* |
| Minimum Active Primary Open Loop Enrichment | `cc170` |  |  | R* |
| Minimum Primary Open Loop Enrichment (Accelerator) | `ccdc0` |  |  | R* |
| Minimum Primary Open Loop Enrichment (Throttle) | `ccda0` |  |  | R* |
| OL Enrichment Ramp Rate | `ce5a4` | 2D | AFLDecayRate | R |
| Primary Open Loop Fuel Map Switch (IAM) | `cc16c` |  |  | R* |
| Primary Open Loop Fueling (Failsafe) | `d05c4` |  |  | R* |
| Primary Open Loop Fueling (Failsafe)(KCA Alternate Mode) | `cfef0` |  |  | R* |
| Primary Open Loop Fueling (KCA Additive B High) | `d0404` |  |  | R* |
| Primary Open Loop Fueling (KCA Additive B Low) | `d0244` |  |  | R* |
| Primary Open Loop Fueling (KCA Alternate Mode) | `cfd30` |  |  | R* |
| Primary Open Loop Fueling Compensation (ECT) | `ce6cc` |  |  | R* |

## Fueling - Closed Loop  (15 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| CL Fueling Target Compensation (ECT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation (ECT)_ | `` | 2D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation (Load) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive)1 | B |
| CL Fueling Target Compensation (Load)(AT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive)1 | B |
| CL Fueling Target Compensation (Load)(MT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive)1 | B |
| CL Fueling Target Compensation A (ECT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation A (ECT)(AT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation A (ECT)(MT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation B (ECT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation B (ECT)(AT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation B (ECT)(MT) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive) | B |
| CL Fueling Target Compensation C (Load) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive)1 | B |
| CL Fueling Target Compensation D (Load) | `` | 3D | EstimatedAir/FuelRatioPoints(Additive)1 | B |
| Front Oxygen Sensor #1 Scaling | `` | 2D | Air/FuelRatio | B |
| Front Oxygen Sensor #2 Scaling | `` | 2D | Air/FuelRatio | B |

## Fueling - Cranking  (40 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Cranking Fuel IPW Compensation (RPM) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation (RPM)(AT) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation (RPM)(MT) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation A (RPM) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation A (RPM)(AT) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation A (RPM)(MT) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation B (RPM) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation B (RPM)(AT) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel IPW Compensation B (RPM)(MT) | `` | 3D | CrankingFuelInjectorPulseWidthCompensation(%) | B |
| Cranking Fuel Injector Pulse Width 1 (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 1A High (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 1A Low (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 1B High (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 1B Low (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 2 (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 2A High (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 2A Low (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 2B High (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 2B Low (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 3A High (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 3A Low (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 3B High (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width 3B Low (ECT) | `` | 3D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width G (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width H (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width I (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width J (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width K (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width L (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width M (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width N (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width O (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width P (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width Q (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width R (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width S (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width T (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Cranking Fuel Injector Pulse Width U (ECT) | `` | 2D | InjectorPulseWidth(ms) | B |
| Post Cranking Airflow Initial Reference Coolant | `` | 2D | MassAirflow(g/s) | B |
| Post Cranking Load Initial Reference Coolant | `` | 2D | EngineLoad(g/rev) | B |

## Fueling - Fuel Cut / Rev Limit  (5 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Overrun Enrich RPM Delta Activation | `cc498` |  |  | R* |
| Overrun Fueling Cut Counter RPM Threshold | `cc4ec` |  |  | R* |
| Overrun Fueling RPM Resume Threshold | `ceed0` |  |  | R* |
| Overrun initial injector enrichment (pulsewidth) | `cc49c` |  |  | R* |
| Rev Limit (Fuel Cut) | `cc500` |  |  | R* |

## Fueling - Injector  (16 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| CL to OL Transition with Delay (Base Pulse Width) | `ce5f8` |  |  | R* |
| Cranking Fuel Injector Pulse Width A (ECT) | `cd2e6` |  |  | R* |
| Cranking Fuel Injector Pulse Width B (ECT) | `cd306` |  |  | R* |
| Cranking Fuel Injector Pulse Width C (ECT) | `cd326` |  |  | R* |
| Cranking Fuel Injector Pulse Width D (ECT) | `cd346` |  |  | R* |
| Cranking Fuel Injector Pulse Width E (ECT) | `cd366` |  |  | R* |
| Cranking Fuel Injector Pulse Width F (ECT) | `cd386` |  |  | R* |
| Injector Flow Scaling | `cbe0c` |  |  | R* |
| Injector Latency_ | `d106c` |  |  | R* |
| Low Pulse Width Fuel Injector Compensation | `d39a8` |  |  | R* |
| Low pulse width fuel injector compensation maximum IPW | `d2d2c` |  |  | R* |
| Low pulse width fuel injector compensation maximum RPM | `d2d28` |  |  | R* |
| Per Injector Pulse Width Compensation A | `d07e8` |  |  | R* |
| Per Injector Pulse Width Compensation B | `d0994` |  |  | R* |
| Per Injector Pulse Width Compensation C | `d0b40` |  |  | R* |
| Per Injector Pulse Width Compensation D | `d0cec` |  |  | R* |

## Fueling - Injectors  (14 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Injector Flow Scaling_ | `` | 2D | ESTIMATEDFlowRate-GasOnly(cc/min) | B |
| Injector Latency | `` | 2D | Latency(ms) | B |
| Per Injector Primary Fuel Offset Compensation A | `` | 3D | InjectorFuelOffsetAdditive1 | B |
| Per Injector Primary Fuel Offset Compensation A_ | `` | 3D | InjectorFuelOffsetAdditive | B |
| Per Injector Primary Fuel Offset Compensation B | `` | 3D | InjectorFuelOffsetAdditive1 | B |
| Per Injector Primary Fuel Offset Compensation B_ | `` | 3D | InjectorFuelOffsetAdditive | B |
| Per Injector Primary Fuel Offset Compensation C | `` | 3D | InjectorFuelOffsetAdditive1 | B |
| Per Injector Primary Fuel Offset Compensation C_ | `` | 3D | InjectorFuelOffsetAdditive | B |
| Per Injector Primary Fuel Offset Compensation D | `` | 3D | InjectorFuelOffsetAdditive1 | B |
| Per Injector Primary Fuel Offset Compensation D_ | `` | 3D | InjectorFuelOffsetAdditive | B |
| Per Injector Pulse Width Compensation E | `` | 3D | InjectorPulseWidthCompensation | B |
| Per Injector Pulse Width Compensation F | `` | 3D | InjectorPulseWidthCompensation | B |
| Per Injector Pulse Width Compensation G | `` | 3D | InjectorPulseWidthCompensation | B |
| Per Injector Pulse Width Compensation H | `` | 3D | InjectorPulseWidthCompensation | B |

## Fueling - Primary Open Loop  (19 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Primary Open Loop Fueling | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling (Failsafe)(KCA Additive B High) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling (Failsafe)(KCA Additive B Low) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling (Failsafe)(KCA Additive High) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling (Failsafe)(KCA Additive Low) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling (KCA Additive High) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling (KCA Additive Low) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling A | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling A (Failsafe) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling A_ | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling Additive | `` | 3D | 'PrimaryOpenLoopFueling'RawEnrichmentOffsetAdditive | B |
| Primary Open Loop Fueling B | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling B (Failsafe) | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling B_ | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling Base | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling Compensation (Timing Compensation) | `` | 2D | 'PrimaryOpenLoopFueling'RawEnrichmentOffsetAdditive | B |
| Primary Open Loop Fueling Cruise | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling Non-Cruise | `` | 3D | EstimatedAir/FuelRatio | B |
| Primary Open Loop Fueling_ | `` | 3D | EstimatedAir/FuelRatio | B |

## Fueling - Tip-in Enrichment  (7 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Throttle Tip-in Enrichment | `` | 2D | AdditionalInjectorPulseWidth(ms)1 | B |
| Tip-in Enrichment Compensation (ECT) | `` | 2D | ThrottleTip-inEnrichmentCompensation(%)2 | B |
| Tip-in Enrichment Compensation (MRP) | `` | 2D | ThrottleTip-inEnrichmentCompensation(%) | B |
| Tip-in Enrichment Compensation D (ECT) Activation_ | `` | 2D | ThrottleAngleChange(%) | B |
| Tip-in Enrichment Compensation D (ECT)_ | `` | 2D | ThrottleTip-inEnrichmentCompensation(%)1 | B |
| Tip-in Enrichment Disable Applied Counter Threshold | `` | 2D | tip-inenrichmentappliedcounter | B |
| Tip-in Enrichment Disable Throttle Cumulative Threshold | `` | 2D | cumulativethrottleanglechange | B |

## Fueling - Warm-Up Enrichment  (17 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Min Primary Base Enrich 2 Decay Step 1 | `` | 2D | DecayStepValue | B |
| Min Primary Base Enrich 2 Decay Step 2 | `` | 2D | DecayStepValue | B |
| Min Primary Base Enrich 2 Initial Start 1A | `` | 2D | InitialAfterstartOffset | B |
| Min Primary Base Enrich 2 Initial Start 1B | `` | 2D | InitialAfterstartOffset | B |
| Min Primary Base Enrich 2 Initial Start 2A | `` | 2D | InitialAfterstartOffset | B |
| Min Primary Base Enrich 2 Initial Start 2B | `` | 2D | InitialAfterstartOffset | B |
| Min Primary Base Enrich 3 Decay Delay A | `` | 2D | Periodin-betweendecaymultiplierapplication | B |
| Min Primary Base Enrich 3 Decay Delay B | `` | 2D | Periodin-betweendecaymultiplierapplication | B |
| Min Primary Base Enrich 3 Decay Multiplier | `` | 2D | Multiplier | B |
| Min Primary Base Enrich 3 Initial Start 1A | `` | 2D | InitialAfterstartOffset1 | B |
| Min Primary Base Enrich 3 Initial Start 1B | `` | 2D | InitialAfterstartOffset1 | B |
| Min Primary Base Enrich 3 Initial Start 2A | `` | 2D | InitialAfterstartOffset1 | B |
| Min Primary Base Enrich 3 Initial Start 2B | `` | 2D | InitialAfterstartOffset1 | B |
| Min Primary Base Enrichment 1 | `` | 2D | MinimumPrimaryEnrichmentOffsetAdditive1 | B |
| Min Primary Base Enrichment 1 (Non-Primary OL) | `` | 3D | MinimumPrimaryEnrichmentOffsetAdditive1 | B |
| Min Primary Base Enrichment 1 A | `` | 3D | MinimumPrimaryEnrichmentOffsetAdditive1 | B |
| Min Primary Base Enrichment 1 B | `` | 3D | MinimumPrimaryEnrichmentOffsetAdditive1 | B |

## Idle Control  (27 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Idle Airflow Min Target Decel Adder (RPM x ECT) | `d7e40` |  |  | R* |
| Idle Airflow Min Target Decel Adder Active Veh Speed A | `d6480` |  |  | R* |
| Idle Airflow Min Target Decel Initial Idle Activation Max Mode Counter | `d6214` |  |  | R* |
| Idle Airflow Min Target Decel Initial Idle Min Airflow A | `d6484` |  |  | R* |
| Idle Airflow Min Target Decel Ramping Adder Decreasing | `d64a4` |  |  | R* |
| Idle Airflow Min Target Decel Ramping Adder Increasing | `d64a8` |  |  | R* |
| Idle Speed Stability A | `d7ee8` |  |  | R* |
| Idle Speed Stability B | `d8084` |  |  | R* |
| Idle Speed Target A | `d6f34` |  |  | R* |
| Idle Speed Target A (AT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target A (MT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target B | `d6f74` |  |  | R* |
| Idle Speed Target B (AT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target B (MT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target C | `d6fb4` |  |  | R* |
| Idle Speed Target C (AT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target C (MT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target D | `d7054` |  |  | R* |
| Idle Speed Target D (AT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target D (MT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target E | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target E (AT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target E (MT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target F | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target F (AT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target F (MT) | `` | 2D | EngineSpeed(RPM) | B |
| Idle Speed Target G | `` | 2D | EngineSpeed(RPM) | B |

## Idle control  (9 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Idle_Airflow_Min_Target_Decel_Adder | `` | 3D | AirflowAdder | B |
| Idle_Airflow_Min_Target_Decel_Adder_Active_Veh_Speed | `` | 1D | VehicleSpeed(MPH) | B |
| Idle_Airflow_Min_Target_Decel_Initial_Idle_Activation_Max_Mode_Counter | `` | 1D | Map_Switching_Cruise_Switch_Min_Delay | B |
| Idle_Airflow_Min_Target_Decel_Initial_Idle_Min_Airflow | `` | 1D | rawecuvalue | B |
| Idle_Airflow_Min_Target_Decel_Ramping_Adder_Decreasing | `` | 1D | negative | B |
| Idle_Airflow_Min_Target_Decel_Ramping_Adder_Increasing | `` | 1D | rawecuvalue | B |
| Target Throttle_Angle_Idle_Airflow_Target | `` | 2D | %1 | B |
| Target Throttle_Angle_Idle_Airflow_Target_Base_Min | `` | 3D | TPS Throttle | B |
| Target Throttle_Angle_Idle_Airflow_Target_Base_Min_App_Max | `` | 1D | %1 | B |

## Ignition Timing  (35 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Base Timing Idle A (In-Gear) | `d31a6` |  |  | R* |
| Base Timing Idle A (Neutral) | `d31c6` |  |  | R* |
| Base Timing Idle B (In-Gear) | `d31b6` |  |  | R* |
| Base Timing Idle B (Neutral) | `d31d6` |  |  | R* |
| Base Timing Idle Minimum | `d319d` |  |  | R* |
| Base Timing Idle Minimum Vehicle Speed Enable | `d2adc` |  |  | R* |
| Base Timing Primary Cruise | `d4714` |  |  | R* |
| Base Timing Primary Non-Cruise | `d48d4` |  |  | R* |
| Base Timing Reference Cruise (AVCS related) | `d4a94` |  |  | R* |
| Base Timing Reference Non-Cruise (AVCS related) | `d4c54` |  |  | R* |
| Ignition Dwell | `d91e0` |  |  | R* |
| Primary Open Loop Fueling Compensation (Timing Compensation)_ | `ccd30` |  |  | R* |
| Timing Comp Maximum RPM (Per Cylinder) | `d2d98` |  |  | R* |
| Timing Comp Minimum Coolant Temp (Per Cylinder) | `d2da0` |  |  | R* |
| Timing Comp Minimum Load (Per Cylinder) | `d2d9c` |  |  | R* |
| Timing Compensation A (IAT) | `d3288` |  |  | R* |
| Timing Compensation A (IAT) Activation | `d4dc8` |  |  | R* |
| Timing Compensation B (IAT) | `d38a0` |  |  | R* |
| Timing Compensation B (IAT) IAM Activation | `d2cf4` |  |  | R* |
| Timing Compensation B (IAT) Max Additive | `d2cd8` |  |  | R* |
| Timing Compensation Imm. Cruise A (ECT) | `d3226` |  |  | R* |
| Timing Compensation Imm. Cruise B (ECT) | `d3236` |  |  | R* |
| Timing Compensation Imm. Non-Cruise A (ECT) | `d3206` |  |  | R* |
| Timing Compensation Imm. Non-Cruise B (ECT) | `d3216` |  |  | R* |
| Timing Compensation Per Cylinder A | `d54b0` |  |  | R* |
| Timing Compensation Per Cylinder B | `d5544` |  |  | R* |
| Timing Compensation Per Cylinder C | `d55d8` |  |  | R* |
| Timing Compensation Per Cylinder D | `d5670` |  |  | R* |
| Timing Compensation Per Gear (1st) | `d5394` |  |  | R* |
| Timing Compensation Per Gear (2nd) | `d53c4` |  |  | R* |
| Timing Compensation Per Gear (3rd) | `d53f4` |  |  | R* |
| Timing Compensation Per Gear (4th) | `d5424` |  |  | R* |
| Timing Compensation Per Gear (5th) | `d5454` |  |  | R* |
| Timing Compensation Per Gear Activation (Load) | `d2d40` |  |  | R* |
| Timing Compensation Per Gear Activation (RPM) | `d2d38` |  |  | R* |

## Ignition Timing - Advance  (67 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Base Timing | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing A | `` | 3D | BaseIgnitionTiming(degreesBTDC)2 | B |
| Base Timing Alternate (ECT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing B | `` | 3D | BaseIgnitionTiming(degreesBTDC)2 | B |
| Base Timing C | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Cruise A | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Cruise B | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Cruise C | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing D | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing E | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing F | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing G | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing H | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle (Above Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle (Below Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC) | B |
| Base Timing Idle (Below Speed Threshold)_ | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle (In-Gear)(Above Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle (In-Gear)(Above Speed Threshold)_ | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle (In-Gear)(Below Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle (Neutral) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (In-Gear)(Above Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (In-Gear)(Above Speed Threshold)(AT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (In-Gear)(Above Speed Threshold)(MT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (In-Gear)(Below Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (In-Gear)(Below Speed Threshold)(AT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (In-Gear)(Below Speed Threshold)(MT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (Neutral)(AT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (Neutral)(MT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle A (Neutral)_ | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Above Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Above Speed Threshold)(AT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Above Speed Threshold)(MT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Above Speed Threshold)(MT)_ | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Above Speed Threshold)_ | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Below Speed Threshold) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Below Speed Threshold)(AT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (In-Gear)(Below Speed Threshold)(MT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (Neutral)(AT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (Neutral)(MT) | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle B (Neutral)_ | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Idle Vehicle Speed Threshold | `` | 2D | VehicleSpeed(MPH) | B |
| Base Timing Non-Cruise D | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Non-Cruise E | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Base Timing Non-Cruise F | `` | 3D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Ignition Timing Post Start | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |
| Knock Correction Advance Additive Range (RPM) | `` | 2D | EngineSpeed(RPM)1 | B |
| Knock Correction Advance Alternate Mode | `` | 1D | KnockCorrectionAdvanceAlternateMode | B |
| Knock Correction Advance Alternate Mode_ | `` | 1D | KnockCorrectionAdvanceAlternateMode | B |
| Knock Correction Advance Alternate Mode__ | `` | 1D | KnockCorrectionAdvanceAlternateMode | B |
| Knock Correction Advance Max | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max A | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Additive (Knock Conditions) | `` | 3D | MaximumKnockCorrectionTimingAdvanceAdditive(degrees) | B |
| Knock Correction Advance Max Additive A (Knock Conditions)(IAM) | `` | 3D | MaximumKnockCorrectionTimingAdvanceAdditive(degrees) | B |
| Knock Correction Advance Max Additive B (Knock Conditions) | `` | 3D | MaximumKnockCorrectionTimingAdvanceAdditive(degrees) | B |
| Knock Correction Advance Max B | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Cruise A | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Cruise B | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Cruise C | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Non-Cruise D | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Non-Cruise E | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Non-Cruise F | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Primary (Knock Conditions High)(IAM) | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Primary (Knock Conditions Low)(IAM) | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Primary Cruise (IAM) | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Knock Correction Advance Max Primary Non-Cruise (IAM) | `` | 3D | MaximumKnockCorrectionTimingAdvance(degrees) | B |
| Minimum Timing | `` | 2D | BaseIgnitionTiming(degreesBTDC)1 | B |

## Ignition Timing - Compensation  (23 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Ignition Timing Compensation MAP Delta (Clutch Depressed) | `` | 2D | IgnitionTimingAdvanceCorrection(degrees) | B |
| Timing Comp Min Load (IAT) | `` | 2D | EngineLoad(g/rev)1 | B |
| Timing Compensation (ECT) | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation (IAT) Activation | `` | 3D | TimingCompensationIntakeTempMapTargetCompensation(%) | B |
| Timing Compensation (IAT) Activation_ | `` | 3D | TimingCompensationIntakeTempMapTargetCompensation(%)1 | B |
| Timing Compensation (MRP) | `` | 3D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation A (ECT) | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation B (ECT) | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation C (ECT) | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation D (ECT) | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Overrun RPM Delta | `` | 2D | EngineSpeed(RPM)1 | B |
| Timing Compensation Per Cylinder A_ | `` | 2D | degreesofcorrection | B |
| Timing Compensation Per Cylinder A__ | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Per Cylinder B_ | `` | 2D | degreesofcorrection | B |
| Timing Compensation Per Cylinder B__ | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Per Cylinder C_ | `` | 2D | degreesofcorrection | B |
| Timing Compensation Per Cylinder C__ | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Per Cylinder D_ | `` | 2D | degreesofcorrection | B |
| Timing Compensation Per Cylinder D__ | `` | 2D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Per Cylinder E | `` | 3D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Per Cylinder F | `` | 3D | IgnitionTimingCorrection(degrees) | B |
| Timing Compensation Per Gear Conversion Multiplier | `` | 1D | rawecuvalue | B |
| Timing Overrun | `` | 2D | IgnitionTimingCorrection(degrees) | B |

## Ignition Timing - Knock  (26 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Advance Multiplier (Initial) | `d2ee0` |  |  | R* |
| Advance Multiplier Step Value | `d2ee4` |  |  | R* |
| Boost Control Disable (Fine Correction) | `c0bf8` |  |  | R* |
| Boost Control Disable Delay (Fine Correction) | `c0bad` |  |  | R* |
| Extended Feedback Correction High RPM Compensation | `d2dd8` |  |  | R* |
| Feedback Correction Minimum Load | `d2da4` |  |  | R* |
| Feedback Correction Negative Advance Delay | `d29de` |  |  | R* |
| Feedback Correction Negative Advance Value | `d2dd0` |  |  | R* |
| Feedback Correction Range (RPM) | `d2dac` |  |  | R* |
| Feedback Correction Retard Limit | `d2dc8` |  |  | R* |
| Feedback Correction Retard Value | `d2dcc` |  |  | R* |
| Fine Correction Advance Delay | `d29ee` |  |  | R* |
| Fine Correction Advance Limit | `d2f44` |  |  | R* |
| Fine Correction Advance Value | `d2f48` |  |  | R* |
| Fine Correction Columns (Load) | `d2f28` |  |  | R* |
| Fine Correction Range (Load) | `d2f7c` |  |  | R* |
| Fine Correction Range (RPM) | `d2f6c` |  |  | R* |
| Fine Correction Retard Limit | `d2f4c` |  |  | R* |
| Fine Correction Retard Value | `d2f50` |  |  | R* |
| Fine Correction Rows (RPM) | `d2f0c` |  |  | R* |
| Knock Correction Advance Max Cruise | `d5904` |  |  | R* |
| Knock Correction Advance Max Non-Cruise | `d5ac4` |  |  | R* |
| Rough Correction Learning Delay (Increasing)_ | `d3c2c` |  |  | R* |
| Rough Correction Minimum KC Advance Map Value | `d2edc` |  |  | R* |
| Rough Correction Range (Load) | `d2ecc` |  |  | R* |
| Rough Correction Range (RPM) | `d2ebc` |  |  | R* |

## Ignition Timing - Knock Control  (11 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Feedback Correction Minimum Load_ | `` | 2D | EngineLoad(g/rev) | B |
| Feedback Correction Negative Advance Delay_ | `` | 2D | 'NoKnock'DelayPeriodforNegativeFeedbackCorrectionAdvance(counterthreshold) | B |
| Feedback Correction Retard Value_ | `` | 2D | PotentialChangeinCurrentFeedbackCorrectionperKnock'Event'(degreesofcorrection) | B |
| Fine Correction Columns (Load)_ | `` | 2D | EngineLoad(g/rev)1 | B |
| Fine Correction Maximum (RPM) | `` | 2D | EngineSpeed(RPM)1 | B |
| Fine Correction Minimum (RPM) | `` | 2D | EngineSpeed(RPM)1 | B |
| Fine Correction Retard Value A | `` | 2D | degreesofcorrection1 | B |
| Fine Correction Retard Value B | `` | 2D | degreesofcorrection1 | B |
| Fine Correction Retard Value_ | `` | 2D | PotentialChangeinFineCorrectionStoredValuePerKnock'Event'(degreesofcorrection) | B |
| Fine Correction Rows (RPM)_ | `` | 2D | EngineSpeed(RPM)1 | B |
| Rough Correction Learning Delay (Increasing) | `` | 2D | RoughCorrection(IAM)PositiveLearningDelay(counterthreshold)1 | B |

## Knock Sensor  (26 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Background_Noise_Base_Smoothing_Factor_High_Rpm_Delta | `` | 1D | Knock | B |
| Background_Noise_Base_Smoothing_Factor_Low_Rpm_Delta | `` | 1D | Knock | B |
| Background_Noise_Delta_Smoothing_Weighting_Factor_RPM_Delta_Threshold_Imm | `` | 1D | Knock | B |
| Background_Noise_Delta_Smoothing_Weighting_Factor_RPM_Delta_Threshold_Short | `` | 1D | Knock | B |
| Background_Noise_Delta_Weighting_Factor_High_RPM_Delta | `` | 1D | Knock | B |
| Background_Noise_Delta_Weighting_Factor_Low_RPM_Delta | `` | 1D | Knock | B |
| Filter_Noise_Level_Weighting_Factor | `` | 1D | Knock | B |
| Filter_Ref_Max_Range_Hysteresis_Corr_Knock_Sen_output_modify | `` | 1D | Knock3 | B |
| Knock_Detection_Minimum_Engine_Run_Time | `` | 1D | Knock2 | B |
| Knock_Sensor_Calibration | `` | 2D | rawecuvalue | B |
| Knock_Threshhold_Level_Final_Limit_Max | `` | 1D | Knock | B |
| Knock_Threshhold_Level_Final_Limit_Min | `` | 1D | Knock | B |
| Knock_threshhold_Filter_Final_Limit_max_modify_pre_final_limit | `` | 1D | Knock | B |
| Knock_threshhold_Filter_background_noise_interv_weight_factor_High_RPM_Delta_Limit_max | `` | 1D | Knock | B |
| Knock_threshhold_Filter_background_noise_interv_weight_factor_High_RPM_Delta_Rpm_delta_ratio | `` | 1D | Knock | B |
| Knock_threshhold_Filter_background_noise_interv_weight_factor_RPM_Delta_Short | `` | 1D | Knock | B |
| Knock_threshold_filter_Background_Noise_interval_Weighting_Factor_Low_RPM_Delta | `` | 2D | Knock4 | B |
| Knock_threshold_filter_Final_Limit_Max_Cyl_1 | `` | 2D | Knock | B |
| Knock_threshold_filter_Final_Limit_Max_Cyl_2 | `` | 2D | Knock | B |
| Knock_threshold_filter_Final_Limit_Max_Cyl_3 | `` | 2D | Knock | B |
| Knock_threshold_filter_Final_Limit_Max_Cyl_4 | `` | 2D | Knock | B |
| Knock_threshold_filter_Final_Limit_Min | `` | 2D | Knock | B |
| Knock_threshold_weight_factor_RPM_Load_Cyl_1 | `` | 3D | Knock | B |
| Knock_threshold_weight_factor_RPM_Load_Cyl_2 | `` | 3D | Knock | B |
| Knock_threshold_weight_factor_RPM_Load_Cyl_3 | `` | 3D | Knock | B |
| Knock_threshold_weight_factor_RPM_Load_Cyl_4 | `` | 3D | Knock | B |

## MAF / Airflow  (8 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| A/F Learning #1 Airflow Ranges | `cc074` |  |  | R* |
| CL MAF Enable Threshold | `cc020` | 1D | ThresholdFloat | R |
| CL MAF Hysteresis OFF | `cbe74` | 1D | Airflow_gs | R |
| CL MAF Hysteresis ON | `cbe70` | 1D | Airflow_gs | R |
| CL to OL Transition Counter Step Value (MAF) | `ce640` |  |  | R* |
| MAF Compensation (IAT) | `c3bb0` |  |  | R* |
| MAF Limit (Maximum) | `c3100` |  |  | R* |
| MAF Sensor Scaling | `d8c9c` |  |  | R* |

## Manifold Pressure Sensor  (1 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Manifold Pressure Sensor Scaling | `` | 2D | psiabsolute | B |

## Map Switching - Cruise/Non-Cruise  (48 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Map Switch Ramping Adder A | `d2a60` | 1D | MapSwitchRatio | R |
| Map Switch Ramping Adder B | `d2a64` | 1D | MapSwitchRatio | R |
| Map Switching Base RPM Threshold | `d2a8c` | 1D | MapSwitchRPM | R |
| Map Switching Blend App Counter Threshold | `d29d4` | 1D | MapSwitchCounter | R |
| Map Switching Cruise Switch Counter A | `d29ac` | 1D | MapSwitchCounter | R |
| Map Switching Cruise Switch Counter B | `d29b0` | 1D | MapSwitchCounter | R |
| Map Switching Cruise Switch Min Delay A | `d29ae` | 1D | MapSwitchCounter | R |
| Map Switching Cruise Switch Min Delay B | `d29b2` | 1D | MapSwitchCounter | R |
| Map Switching ECT Cold Threshold High | `d2a44` | 1D | MapSwitchTemp | R |
| Map Switching ECT Cold Threshold Low | `d2a40` | 1D | MapSwitchTemp | R |
| Map Switching ECT Compensation A | `d2a90` | 1D | MapSwitchFloat | R |
| Map Switching ECT Compensation B | `d2a94` | 1D | MapSwitchFloat | R |
| Map Switching ECT Threshold | `d2a98` | 1D | MapSwitchTemp | R |
| Map Switching ECT/IAT Hot Threshold A | `d2a50` | 1D | MapSwitchTemp | R |
| Map Switching ECT/IAT Hot Threshold B | `d2a54` | 1D | MapSwitchTemp | R |
| Map Switching Engine Speed Hysteresis High | `d2aac` | 1D | MapSwitchRPM | R |
| Map Switching Engine Speed Hysteresis Low | `d2aa8` | 1D | MapSwitchRPM | R |
| Map Switching Engine Speed Threshold | `d2a08` | 1D | MapSwitchRPM | R |
| Map Switching IAT Threshold | `d2a1c` | 1D | MapSwitchTemp | R |
| Map Switching Idle Mode Threshold | `d2a34` | 1D | MapSwitchFloat | R |
| Map Switching Load Override Threshold | `d2aa0` | 1D | MapSwitchFloat | R |
| Map Switching MAF Sensor Threshold A | `d2a68` | 1D | MapSwitchFloat | R |
| Map Switching MAF Sensor Threshold B | `d2a6c` | 1D | MapSwitchFloat | R |
| Map Switching MAF/Load Threshold | `d2a10` | 1D | MapSwitchFloat | R |
| Map Switching Per-Gear RPM Threshold 1 | `d2a74` | 1D | MapSwitchRPM | R |
| Map Switching Per-Gear RPM Threshold 2 | `d2a78` | 1D | MapSwitchRPM | R |
| Map Switching Per-Gear RPM Threshold 3 | `d2a7c` | 1D | MapSwitchRPM | R |
| Map Switching Per-Gear RPM Threshold 4 | `d2a80` | 1D | MapSwitchRPM | R |
| Map Switching Per-Gear RPM Threshold 5 | `d2a84` | 1D | MapSwitchRPM | R |
| Map Switching Per-Gear RPM Threshold 6 | `d2a88` | 1D | MapSwitchRPM | R |
| Map Switching Percentage Ceiling | `d2abc` | 1D | MapSwitchFloat | R |
| Map Switching RPM Override Threshold | `d2a9c` | 1D | MapSwitchRPM | R |
| Map Switching Ratio Maximum Bound | `d2ab4` | 1D | MapSwitchFloat | R |
| Map Switching Ratio Minimum Bound | `d2ab0` | 1D | MapSwitchFloat | R |
| Map Switching Ratio Modifier Min | `d2a58` | 1D | MapSwitchFloat | R |
| Map Switching Ratio Modifier Scale | `d2a5c` | 1D | MapSwitchFloat | R |
| Map Switching Requested Torque Min | `d2a70` | 1D | MapSwitchFloat | R |
| Map Switching Requested Torque Ratio Threshold | `d2a0c` | 1D | MapSwitchRatio | R |
| Map Switching SI-Drive Mode Threshold | `d2a38` | 1D | MapSwitchFloat | R |
| Map Switching Secondary IAT Threshold | `d2a30` | 1D | MapSwitchTemp | R |
| Map Switching Secondary Load Threshold | `d2a24` | 1D | MapSwitchFloat | R |
| Map Switching Secondary SI-Drive Value | `d2a3c` | 1D | MapSwitchFloat | R |
| Map Switching Secondary Torque Threshold | `d2a20` | 1D | MapSwitchFloat | R |
| Map Switching Secondary Vehicle Speed High | `d2a2c` | 1D | MapSwitchFloat | R |
| Map Switching Secondary Vehicle Speed Low | `d2a28` | 1D | MapSwitchFloat | R |
| Map Switching Speed/Load Check Value | `d2aa4` | 1D | MapSwitchFloat | R |
| Map Switching Vehicle Speed High Threshold | `d2a18` | 1D | MapSwitchFloat | R |
| Map Switching Vehicle Speed Low Threshold | `d2a14` | 1D | MapSwitchFloat | R |

## Map Switching - Timing Blend  (14 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Timing Blend Correction Offset | `d2afc` | 1D | MapSwitchDegrees | R |
| Timing Blend Correction Threshold | `d2b08` | 1D | MapSwitchDegrees | R |
| Timing Blend Half Ratio (Map Ratio E42) | `d2b0c` | 1D | MapSwitchRatio | R |
| Timing Blend IAT Threshold A | `d2af4` | 1D | MapSwitchTemp | R |
| Timing Blend IAT Threshold B | `d2af8` | 1D | MapSwitchTemp | R |
| Timing Blend Lookup Input Threshold | `d2ae8` | 1D | MapSwitchFloat | R |
| Timing Blend Minimum Ratio | `d2b10` | 1D | MapSwitchFloat | R |
| Timing Blend RPM Activation Threshold | `d2aec` | 1D | MapSwitchRPM | R |
| Timing Blend RPM Limit | `d2b14` | 1D | MapSwitchRPM | R |
| Timing Blend RPM Max for Blending | `d2b00` | 1D | MapSwitchRPM | R |
| Timing Blend RPM Secondary Threshold | `d2af0` | 1D | MapSwitchRPM | R |
| Timing Blend Ramping Rate | `d2b04` | 1D | MapSwitchRatio | R |
| Timing Blend Ratio Ceiling | `d2b1c` | 1D | MapSwitchRatio | R |
| Timing Blend Ratio Floor | `d2b18` | 1D | MapSwitchFloat | R |

## Mass Airflow / Engine Load  (11 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Engine Load Compensation (MP) | `` | 3D | EngineLoadCompensation(%) | B |
| Engine Load Compensation A (MP) | `` | 3D | EngineLoadCompensation(%) | B |
| Engine Load Compensation A (Throttle) | `` | 3D | EngineLoadCompensation(%) | B |
| Engine Load Compensation B (MP) | `` | 3D | EngineLoadCompensation(%) | B |
| Engine Load Compensation B (Throttle) | `` | 3D | EngineLoadCompensation(%) | B |
| Engine Load Limit (Maximum) | `` | 2D | EngineLoad(g/rev)1 | B |
| Engine Load Limit B (Maximum) | `` | 2D | EngineLoad(g/rev)1 | B |
| Load B Max(RPM) mul | `` | 2D | multiplier | B |
| MAF Compensation A (IAT) | `` | 3D | MassAirflowCompensation(%) | B |
| MAF Compensation B (IAT) | `` | 3D | MassAirflowCompensation(%) | B |
| MAF Limit (Maximum)_ | `` | 2D | MassAirflow(g/s) | B |

## MerpMod Speed Density  (6 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| MerpMod SD - Atmospheric Compensation | `db450` | 3D | MerpMod_AtmComp | M |
| MerpMod SD - Celsius to Kelvin | `dae8c` | 1D | MerpMod_Float | M |
| MerpMod SD - Engine Displacement | `dae94` | 1D | MerpMod_Float | M |
| MerpMod SD - MAF/SD Blending Ratio | `db520` | 3D | MerpMod_BlendRatio | M |
| MerpMod SD - Speed Density Constant | `dae90` | 1D | MerpMod_Float | M |
| MerpMod SD - Volumetric Efficiency 1 | `daf7c` | 3D | MerpMod_VE | M |

## MerpMod Speed Density - RAM  (7 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| MerpMod SD - Atmospheric Compensation (live) | `ffc01c` | 1D | MerpMod_Float | M |
| MerpMod SD - Blend Ratio (live) | `ffc024` | 1D | MerpMod_Float | M |
| MerpMod SD - Blended MAF Output (live) | `ffc028` | 1D | MerpMod_Float | M |
| MerpMod SD - MAF Mode | `ffc00d` | 1D | MerpMod_MafMode | M |
| MerpMod SD - MAF from SD (live) | `ffc014` | 1D | MerpMod_Float | M |
| MerpMod SD - MAF from Sensor (live) | `ffc018` | 1D | MerpMod_Float | M |
| MerpMod SD - Volumetric Efficiency (live) | `ffc010` | 1D | MerpMod_Float | M |

## Miscellaneous - Limits  (10 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Rev Limit A | `` | 2D | EngineSpeed(RPM)1 | B |
| Rev Limit B | `` | 2D | EngineSpeed(RPM)1 | B |
| Rev Limit Fuel Resume (MP) | `` | 2D | ManifoldPressure(psirelativesealevel) | B |
| Speed Limiting (Fuel Cut) | `` | 2D | VehicleSpeed(MPH) | B |
| Speed Limiting (Throttle) | `` | 2D | VehicleSpeed(MPH) | B |
| Speed Limiting (Throttle)_ | `` | 2D | VehicleSpeed(MPH) | B |
| Speed Limiting A (Throttle) | `` | 2D | VehicleSpeed(MPH) | B |
| Speed Limiting A (Throttle) SI-DRIVE Intelligent | `` | 2D | VehicleSpeed(MPH) | B |
| Speed Limiting B (Throttle) | `` | 2D | VehicleSpeed(MPH) | B |
| Speed Limiting B (Throttle) SI-DRIVE Intelligent | `` | 2D | VehicleSpeed(MPH) | B |

## Miscellaneous - Sensor Scalings  (4 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Atmospheric Pressure Sensor Scaling | `` | 2D | psi | B |
| Atmospheric Pressure Sensor Scaling_ | `` | 2D | psi | B |
| EGT Sensor Scaling | `` | 2D | Temperature(DegreesF) | B |
| Oil Temp Sensor Scaling | `` | 2D | Temperature(DegreesF) | B |

## Miscellaneous - Thresholds  (4 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Gear Determination Thresholds | `` | 2D | Rev/Mile | B |
| Radiator Fan Modes (ECT) | `` | 2D | CoolantTemp(DegreesF) | B |
| Radiator Fan Modes C (ECT) | `` | 2D | CoolantTemp(DegreesF) | B |
| Radiator Fan Modes D (ECT) | `` | 2D | CoolantTemp(DegreesF) | B |

## Misfire  (3 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Misfire Count MAP Threshold | `` | 2D | Pressure (bar) | B |
| Misfire DTC Threshold | `` | 3D | MisfireDTCThreshold | B |
| X | `` | X Axis | RPM | B* |

## OBD-II  (2 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Force Pass Readiness Monitors | `` | 1D | ForcePassReadinessMonitors | B |
| Force Pass Readiness Monitors_ | `` | 1D | ForcePassReadinessMonitors_ | B |

## Sensors / Calibration  (11 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Barometric Pressure Offset | `d8adc` | 1D | MapSwitchFloat | R |
| Coolant Temp Sensor Scaling | `d8e4c` |  |  | R* |
| Engine Load Compensation Cruise (MP) | `c3c3c` |  |  | R* |
| Engine Load Compensation Non-Cruise (MP) | `c3d3c` |  |  | R* |
| Engine Load Limit A (Maximum) | `20384` |  |  | R* |
| Engine Load Limit B Maximum (RPM) | `c3608` |  |  | R* |
| Fuel Temp Sensor Scaling | `d9024` |  |  | R* |
| Intake Temp Sensor Scaling | `d8f34` |  |  | R* |
| Manifold Pressure Sensor CEL Delays | `d8a39` |  |  | R* |
| Manifold Pressure Sensor Limits (CEL) | `d8a88` |  |  | R* |
| Manifold Pressure Sensor Scaling_ | `d8ad8` |  |  | R* |

## Torque Management / DBW  (24 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| MAF Hysteresis A OFF (CL/OL) | `cc58c` | 1D | Airflow_gs | R |
| MAF Hysteresis A ON (CL/OL) | `cc588` | 1D | Airflow_gs | R |
| MAF Hysteresis B OFF (CL/OL) | `cc594` | 1D | Airflow_gs | R |
| MAF Hysteresis B ON (CL/OL) | `cc590` | 1D | Airflow_gs | R |
| MAF Hysteresis C OFF (CL/OL) | `cc59c` | 1D | Airflow_gs | R |
| MAF Hysteresis C ON (CL/OL) | `cc598` | 1D | Airflow_gs | R |
| MAF Hysteresis D ON (CL/OL) | `cc5a0` | 1D | Airflow_gs | R |
| Requested Torque (Accelerator Pedal) SI-DRIVE Intelligent | `f9ee0` |  |  | R* |
| Requested Torque (Accelerator Pedal) SI-DRIVE Sport | `f99e0` |  |  | R* |
| Requested Torque (Accelerator Pedal) SI-DRIVE Sport Sharp | `f9c60` |  |  | R* |
| Requested Torque Base (RPM) | `f8b54` |  |  | R* |
| Requested Torque Limit A (Per Gear/Engine Speed) | `f9788` |  |  | R* |
| Requested Torque Limit B (Per Gear/Engine Speed) | `f98a0` |  |  | R* |
| Speed Limiting (Throttle) SI-DRIVE Intelligent | `f8954` |  |  | R* |
| Speed Limiting A (Throttle) SI-DRIVE Sport/Sport Sharp | `f8948` |  |  | R* |
| Speed Limiting B (Throttle) SI-DRIVE Sport/Sport Sharp | `f8960` |  |  | R* |
| Speed Limiting Disable (Fuel Cut) | `cc528` |  |  | R* |
| Speed Limiting Enable (Fuel Cut) | `cc520` |  |  | R* |
| Target Throttle Plate Position Cruise (Requested Torque Ratio) | `f9004` |  |  | R* |
| Target Throttle Plate Position Maximum (Requested Torque Ratio) | `f9504` |  |  | R* |
| Target Throttle Plate Position Non-Cruise (Requested Torque Ratio) | `f9284` |  |  | R* |
| Torque Request MAF Maximum | `cc578` | 1D | Airflow_gs | R |
| Torque Request MAF Upper Gate | `cc574` | 1D | Airflow_gs | R |
| Torque Request Minimum APP | `cc570` | 1D | ThresholdFloat | R |

## Variable Valve Timing (AVCS)  (18 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Exhaust Cam Retard Angle (ECT Related) | `` | 3D | Advance(degrees)3 | B |
| Exhaust Cam Retard Angle (ECT Related) Multiplier | `` | 2D | Multiplier1 | B |
| Exhaust Cam Retard Angle A (AVCS) | `` | 3D | Retard(degrees) | B |
| Exhaust Cam Retard Angle B (AVCS) | `` | 3D | Retard(degrees) | B |
| Exhaust Cam Retard Angle Cruise (AVCS) | `` | 3D | Retard(degrees) | B |
| Exhaust Cam Retard Angle Cruise (AVCS)_ | `` | 3D | Retard(degrees)1 | B |
| Exhaust Cam Retard Angle Cruise (AVCS)__ | `` | 3D | Retard(degrees)2 | B |
| Exhaust Cam Retard Angle Non-Cruise (AVCS) | `` | 3D | Retard(degrees) | B |
| Exhaust Cam Retard Angle Non-Cruise (AVCS)_ | `` | 3D | Retard(degrees)1 | B |
| Exhaust Cam Retard Angle Non-Cruise (AVCS)__ | `` | 3D | Retard(degrees)2 | B |
| Intake Cam Advance Angle (AVCS) | `` | 3D | Advance(degrees) | B |
| Intake Cam Advance Angle (ECT Related) Multiplier | `` | 2D | Multiplier1 | B |
| Intake Cam Advance Angle A (AVCS) | `` | 3D | Advance(degrees) | B |
| Intake Cam Advance Angle B (AVCS) | `` | 3D | Advance(degrees) | B |
| Intake Cam Advance Angle Cruise (AVCS)_ | `` | 3D | Advance(degrees)1 | B |
| Intake Cam Advance Angle Cruise (AVCS)__ | `` | 3D | Advance(degrees)2 | B |
| Intake Cam Advance Angle Non-Cruise (AVCS)_ | `` | 3D | Advance(degrees)1 | B |
| Intake Cam Advance Angle Non-Cruise (AVCS)__ | `` | 3D | Advance(degrees)2 | B |

## Vehicle Speed / Transmission  (7 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Calculated Engine Torque A | `c1800` |  |  | R* |
| Calculated Engine Torque B | `c1a80` |  |  | R* |
| Calculated Engine Torque C | `c1d00` |  |  | R* |
| Calculated Engine Torque D | `c1f80` |  |  | R* |
| Gear Determination Thresholds A | `c3474` |  |  | R* |
| Gear Determination Thresholds B | `c3488` |  |  | R* |
| Gear Determination Thresholds C | `c349c` |  |  | R* |

## tinywrex patches  (14 tables)

| Name | Addr | Type | Scaling | Src |
|---|---|---|---|---|
| Boost disable during fuel cut-Boost(bar) threshold | `c0bc8` | 1D | barpressureabsolute | R |
| Boost disable during fuel cut-Boost(psi) threshold | `c0bc8` | 1D | psipressureabsolute | R |
| Boost disable during fuel cut-Load threshold | `c0bcc` | 1D | EngineLoad(g/rev) | R |
| Boost disable during fuel cut-RPM threshold | `c0bd0` | 1D | LCRPM | R |
| FFS RPM delta | `f1054` | 1D | LCRPM | R |
| LC RPM delta | `f1050` | 1D | LCRPM | R |
| LC disable speed(KMH)threshold | `f104c` | 1D | LCSPEED(KMH) | R |
| LC disable speed(MPH)threshold | `f104c` | 1D | LCSPEED(MPH) | R |
| Rev Limit Off | `cc504` | 1D | LCRPM | R |
| Rev Limit Off (2) | `cc50c` | 1D | LCRPM | R |
| Rev Limit Off (3) | `cc514` | 1D | LCRPM | R |
| Rev Limit On | `cc500` | 1D | LCRPM | R |
| Rev Limit On (2) | `cc508` | 1D | LCRPM | R |
| Rev Limit On (3) | `cc510` | 1D | LCRPM | R |

