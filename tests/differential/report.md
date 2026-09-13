# Differential report

- mode: `selftest`
- binary: `(selftest fake runners)`
- golden corpus: `tests/fixtures/golden/`
- cases run: 36

| status | count |
|--------|-------|
| PASS | 12 |
| FAIL | 12 |
| SKIP | 12 |

**12 case(s) failed parity check.**

## `findrefs_string_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `string Context`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (28, 28)

## `findrefs_type_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `type ClockFaceView`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (2, 2)

## `findrefs_method_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (17, 17)

## `findrefs_method_precise_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onLayout --class Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `0`

## `findrefs_field_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field textColor`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (16, 16)

## `findrefs_field_fuzzy_class_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field gradientColors --class ClockFaceView --fuzzy-class`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (2, 2)

## `getclass_clockface_workload` — PASS

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `0`

## `findrefs_string_aurora` — PASS

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (41, 41)
  - `classes2.dex`: (15, 15)

## `findrefs_type_aurora` — PASS

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `type Fragment`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (8, 8)
  - `classes2.dex`: (176, 176)

## `findrefs_method_aurora` — PASS

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (6, 6)
  - `classes2.dex`: (4, 4)

## `findrefs_string_fdroid` — PASS

- subcommand: `findrefs`
- apk: `org.fdroid.fdroid_1016000.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (10, 10)
  - `classes2.dex`: (14, 14)

## `getclass_notfound` — PASS

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lno/such/Class;`
- oracle exit: `1` ; bin exit: `1`

## `findrefs_string_workload` — FAIL

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `string Context`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=24 extra=2
- matched_method_count golden=24 bin=2
  - matched methods missing in bin (truncated):
    - `Landroidx/appcompat/app/AppCompatViewInflater$DeclaredOnClickListener;->resolveMethod`
    - `Landroidx/core/app/NotificationCompat$Action$Builder;->checkContextualActionNullFields`
    - `Landroidx/core/content/ContextCompat$Api30Impl;->getDisplayOrDefault`
    - `Landroidx/core/content/ContextCompat;->createFilesDir`
    - `Landroidx/core/graphics/TypefaceCompat;->create`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=24 extra=2
  - missing lines (truncated):
    - `classes.dex | Landroidx/appcompat/app/AppCompatViewInflater$DeclaredOnClickListener;->resolveMethod | matched=((View) in a parent or ancestor Context for android:onClick attribute defined on view )`
    - `classes.dex | Landroidx/core/app/NotificationCompat$Action$Builder;->checkContextualActionNullFields | matched=(Contextual Actions must contain a valid PendingIntent)`
    - `classes.dex | Landroidx/core/content/ContextCompat$Api30Impl;->getDisplayOrDefault | matched=(ContextCompat)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (28, 1)

## `findrefs_type_workload` — FAIL

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `type ClockFaceView`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=2 extra=2
- matched_method_count golden=2 bin=2
  - matched methods missing in bin (truncated):
    - `Lcom/google/android/material/timepicker/ClockFaceView;-><init>`
    - `Lcom/google/android/material/timepicker/TimePickerView;-><init>`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=2 extra=2
  - missing lines (truncated):
    - `classes.dex | Lcom/google/android/material/timepicker/ClockFaceView;-><init> | matched=(Lcom/google/android/material/timepicker/ClockFaceView$1;; Lcom/google/android/material/timepicker/ClockFaceView$`
    - `classes.dex | Lcom/google/android/material/timepicker/TimePickerView;-><init> | matched=(Lcom/google/android/material/timepicker/ClockFaceView;)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (2, 1)

## `findrefs_method_workload` — FAIL

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=17 extra=2
- matched_method_count golden=17 bin=2
  - matched methods missing in bin (truncated):
    - `Landroidx/appcompat/app/ActionBarDrawerToggle$1;->onClick`
    - `Landroidx/appcompat/app/AlertController$AlertParams$3;->onItemClick`
    - `Landroidx/appcompat/app/AlertController$AlertParams$4;->onItemClick`
    - `Landroidx/appcompat/app/AlertController$ButtonHandler;->handleMessage`
    - `Landroidx/appcompat/widget/SearchView;->onItemClicked`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=17 extra=2
  - missing lines (truncated):
    - `classes.dex | Landroidx/appcompat/app/ActionBarDrawerToggle$1;->onClick | matched=(Landroid/view/View$OnClickListener;->onClick)`
    - `classes.dex | Landroidx/appcompat/app/AlertController$AlertParams$3;->onItemClick | matched=(Landroid/content/DialogInterface$OnClickListener;->onClick)`
    - `classes.dex | Landroidx/appcompat/app/AlertController$AlertParams$4;->onItemClick | matched=(Landroid/content/DialogInterface$OnMultiChoiceClickListener;->onClick)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (17, 1)

## `findrefs_method_precise_workload` — FAIL

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onLayout --class Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=0 extra=2
- matched_method_count golden=0 bin=2
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=0 extra=2
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (0, 1)

## `findrefs_field_workload` — FAIL

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field textColor`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=16 extra=2
- matched_method_count golden=16 bin=2
  - matched methods missing in bin (truncated):
    - `Landroidx/appcompat/widget/SuggestionsAdapter;->formatUrl`
    - `Landroidx/appcompat/widget/SwitchCompat;->setSwitchTextAppearance`
    - `Lcom/google/android/material/datepicker/CalendarItemStyle;-><init>`
    - `Lcom/google/android/material/datepicker/CalendarItemStyle;->styleItem`
    - `Lcom/google/android/material/internal/NavigationMenuPresenter$NavigationMenuAdapter;->onBindViewHolder`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=16 extra=2
  - missing lines (truncated):
    - `classes.dex | Landroidx/appcompat/widget/SuggestionsAdapter;->formatUrl | matched=(Landroidx/appcompat/R$attr;->textColorSearchUrl)`
    - `classes.dex | Landroidx/appcompat/widget/SwitchCompat;->setSwitchTextAppearance | matched=(Landroidx/appcompat/R$styleable;->TextAppearance_android_textColor)`
    - `classes.dex | Lcom/google/android/material/datepicker/CalendarItemStyle;-><init> | matched=(Lcom/google/android/material/datepicker/CalendarItemStyle;->textColor)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (16, 1)

## `findrefs_field_fuzzy_class_workload` — FAIL

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field gradientColors --class ClockFaceView --fuzzy-class`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=2 extra=2
- matched_method_count golden=2 bin=2
  - matched methods missing in bin (truncated):
    - `Lcom/google/android/material/timepicker/ClockFaceView;-><init>`
    - `Lcom/google/android/material/timepicker/ClockFaceView;->getGradientForTextView`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=2 extra=2
  - missing lines (truncated):
    - `classes.dex | Lcom/google/android/material/timepicker/ClockFaceView;-><init> | matched=(Lcom/google/android/material/timepicker/ClockFaceView;->gradientColors)`
    - `classes.dex | Lcom/google/android/material/timepicker/ClockFaceView;->getGradientForTextView | matched=(Lcom/google/android/material/timepicker/ClockFaceView;->gradientColors)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (2, 1)

## `getclass_clockface_workload` — FAIL

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `0`
- reason: decompiled source mismatch (11730B vs 110B)
- bin stdout preview (truncated):
  ```
  WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)
  classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)
  ```

## `findrefs_string_aurora` — FAIL

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=56 extra=2
- matched_method_count golden=56 bin=2
  - matched methods missing in bin (truncated):
    - `LA3/a;->onClick`
    - `LA3/b;->onClick`
    - `LA3/c;->onClick`
    - `LB3/g;->h`
    - `LB3/i;->onClick`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=56 extra=2
  - missing lines (truncated):
    - `classes.dex | LC/A;->b | matched=(This log indicates a hard-to-reproduce Compose issue, modified with additional debugging details. Please help us by adding your experiences to the bug link provided. `
    - `classes.dex | LL/q;->d | matched=(). Please report to Google or use https://goo.gle/compose-feedback)`
    - `classes.dex | LT1/a;->b | matched=(onAutoCloseCallback is null but it should have been set before use. Please file a bug against Room at: https://issuetracker.google.com/issues/new?component=413107&te`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (41, 1)
  - `classes2.dex`: (15, 0)

## `findrefs_type_aurora` — FAIL

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `type Fragment`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=184 extra=2
- matched_method_count golden=184 bin=2
  - matched methods missing in bin (truncated):
    - `LA3/a;->onClick`
    - `LA3/b;->onClick`
    - `LA3/c;->onClick`
    - `LA3/d;->onClick`
    - `LA3/k;->I`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=184 extra=2
  - missing lines (truncated):
    - `classes.dex | LD1/A;->onCreateView | matched=(Landroidx/fragment/app/FragmentContainerView;)`
    - `classes.dex | LD1/F;->C0 | matched=(Landroidx/fragment/app/FragmentContainerView;)`
    - `classes.dex | LD1/L;->f | matched=(Landroidx/fragment/app/FragmentContainerView;)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (8, 1)
  - `classes2.dex`: (176, 0)

## `findrefs_method_aurora` — FAIL

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=10 extra=2
- matched_method_count golden=10 bin=2
  - matched methods missing in bin (truncated):
    - `LP1/b$a;->onClick`
    - `Landroidx/appcompat/app/AlertController$c;->handleMessage`
    - `Landroidx/appcompat/app/b;->onItemClick`
    - `Landroidx/appcompat/app/c;->onItemClick`
    - `Landroidx/appcompat/widget/SearchView;->t`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=10 extra=2
  - missing lines (truncated):
    - `classes.dex | LP1/b$a;->onClick | matched=(Landroidx/preference/b;->onClick)`
    - `classes.dex | Landroidx/appcompat/app/AlertController$c;->handleMessage | matched=(Landroid/content/DialogInterface$OnClickListener;->onClick)`
    - `classes.dex | Landroidx/appcompat/app/b;->onItemClick | matched=(Landroid/content/DialogInterface$OnClickListener;->onClick)`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (6, 1)
  - `classes2.dex`: (4, 0)

## `findrefs_string_fdroid` — FAIL

- subcommand: `findrefs`
- apk: `org.fdroid.fdroid_1016000.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `0`
- reason: line set mismatch: missing=24 extra=2
- matched_method_count golden=24 bin=2
  - matched methods missing in bin (truncated):
    - `Landroidx/core/text/util/LinkifyCompat;->addLinks`
    - `Landroidx/room/AutoCloser$2;->run`
    - `Landroidx/room/AutoCloser;->incrementCountAndEnsureDbIsOpen`
    - `Landroidx/room/AutoCloser;->init`
    - `Linfo/guardianproject/netcipher/proxy/OrbotHelper;->getOrbotInstallIntent`
  - matched methods extra in bin (truncated):
    - `Lbogus/Cls;->bogus`
    - `Lbogus/Cls;->bogus2`
- line set: missing=24 extra=2
  - missing lines (truncated):
    - `classes.dex | Landroidx/core/text/util/LinkifyCompat;->addLinks | matched=(https://)`
    - `classes.dex | Landroidx/room/AutoCloser$2;->run | matched=(mOnAutoCloseCallback is null but it should have been set before use. Please file a bug against Room at: https://issuetracker.google.com/issue`
    - `classes.dex | Landroidx/room/AutoCloser;->incrementCountAndEnsureDbIsOpen | matched=(AutoCloser has not been initialized. Please file a bug against Room at: https://issuetracker.google.com/issues/new?`
  - extra lines (truncated):
    - `WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)`
    - `classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)`
- per-dex counts (golden, bin):
  - `WRONG DEX`: (0, 1)
  - `classes.dex`: (10, 1)
  - `classes2.dex`: (14, 0)

## `getclass_notfound` — FAIL

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lno/such/Class;`
- oracle exit: `1` ; bin exit: `0`
- reason: exit code mismatch: oracle=1 bin=0 (oracle stderr='Error: Class Lno/such/Class; not found in APK.' bin stderr='')

## `findrefs_string_workload` — SKIP

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `string Context`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_type_workload` — SKIP

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `type ClockFaceView`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_method_workload` — SKIP

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_method_precise_workload` — SKIP

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onLayout --class Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_field_workload` — SKIP

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field textColor`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_field_fuzzy_class_workload` — SKIP

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field gradientColors --class ClockFaceView --fuzzy-class`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `getclass_clockface_workload` — SKIP

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_string_aurora` — SKIP

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_type_aurora` — SKIP

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `type Fragment`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_method_aurora` — SKIP

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `findrefs_string_fdroid` — SKIP

- subcommand: `findrefs`
- apk: `org.fdroid.fdroid_1016000.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `99`
- reason: fake skip runner always returns 99

## `getclass_notfound` — SKIP

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lno/such/Class;`
- oracle exit: `1` ; bin exit: `99`
- reason: fake skip runner always returns 99

