# Radio Communications Crash Course

## Table of Contents

### Stage 1: Radio Fundamentals
- [Electromagnetic Spectrum](#electromagnetic-spectrum)
- [Radio Frequency Basics](#radio-frequency-basics)
- [Wave Properties](#wave-properties)
- [Decibels & Power](#decibels--power)
- [Basic Components](#basic-components)
- [Signal Quality Metrics](#signal-quality-metrics)

### Stage 2: Modulation & Transmission
- [Why Modulation?](#why-modulation)
- [Analog Modulation](#analog-modulation)
- [Digital Modulation](#digital-modulation)
- [Spread Spectrum](#spread-spectrum)
- [Multiple Access](#multiple-access)
- [Transmitter Design](#transmitter-design)
- [Receiver Design](#receiver-design)

### Stage 3: Antennas & Propagation
- [Antenna Fundamentals](#antenna-fundamentals)
- [Antenna Types](#antenna-types)
- [Antenna Arrays](#antenna-arrays)
- [Antenna Measurements](#antenna-measurements)
- [Propagation Mechanisms](#propagation-mechanisms)
- [Path Loss Models](#path-loss-models)
- [Fading & Multipath](#fading--multipath)

---

# Stage 1: Radio Fundamentals

## Electromagnetic Spectrum

### The Big Picture
Radio waves are electromagnetic radiation - same family as light, just different frequency.

```
Frequency (Hz)    Wavelength    Name           Use
3 Hz - 30 Hz      100,000km+    ELF           Submarine comms
30 Hz - 300 Hz    10,000km      SLF           Military
300 Hz - 3 kHz    1,000km       ULF           Navigation
3 kHz - 30 kHz    100km         VLF           Navigation, time signals
30 kHz - 300 kHz  10km          LF            AM radio (Europe)
300 kHz - 3 MHz   1km           MF            AM radio, maritime
3 MHz - 30 MHz    100m          HF            Shortwave, amateur radio
30 MHz - 300 MHz  10m           VHF           FM radio, TV, aviation
300 MHz - 3 GHz   1m            UHF           TV, cell phones, GPS
3 GHz - 30 GHz    10cm          SHF           Satellite, radar
30 GHz - 300 GHz  1cm           EHF           Experimental, astronomy
```

### Key Insight
Higher frequency = shorter wavelength = more directional = shorter range (generally)

## Radio Frequency Basics

### Frequency vs Wavelength
```
c = f × λ
c = speed of light (3×10⁸ m/s)
f = frequency (Hz)
λ = wavelength (m)
```

**Quick calculations:**
- 100 MHz → λ = 3m
- 2.4 GHz → λ = 12.5cm
- 433 MHz → λ = 69cm

### Frequency Bands (ITU Regions)
```
Band    Frequency       Wavelength    Applications
LF      30-300 kHz      10-1 km       RFID, navigation
MF      300 kHz-3 MHz   1000-100 m    AM broadcast
HF      3-30 MHz        100-10 m      Shortwave, amateur
VHF     30-300 MHz      10-1 m        FM, TV, aviation
UHF     300 MHz-3 GHz   100-10 cm     Cell, WiFi, Bluetooth
SHF     3-30 GHz        10-1 cm       Satellite, radar
EHF     30-300 GHz      10-1 mm       5G mmWave
```

## Wave Properties

### Basic Wave Characteristics

**Amplitude (A)**: Signal strength
```
Power = A²
Voltage doubles = 4x power = +6dB
```

**Frequency (f)**: Cycles per second (Hz)
```
1 kHz = 1,000 Hz
1 MHz = 1,000,000 Hz  
1 GHz = 1,000,000,000 Hz
```

**Phase (φ)**: Time relationship between waves
```
0° = In phase (signals add)
180° = Out of phase (signals cancel)
90° = Quadrature (power combines differently)
```

**Wavelength (λ)**: Physical distance of one cycle
```
Quarter wave (λ/4) = optimal antenna length
Half wave (λ/2) = dipole antenna
Full wave (λ) = loop antenna
```

### Wave Behavior

**Reflection**: Bounces off surfaces
- Metal surfaces: nearly 100% reflection
- Ground/buildings: partial reflection
- Ionosphere: HF reflection (skip propagation)

**Refraction**: Bends through different mediums
- Atmosphere layers bend VHF/UHF
- Temperature/humidity effects

**Diffraction**: Bends around obstacles
- Lower frequencies bend more
- VHF can bend around hills
- UHF needs line-of-sight

**Absorption**: Energy lost to materials
- Rain absorbs microwaves heavily
- Foliage absorbs VHF/UHF
- Human body absorbs 2.4 GHz

## Decibels & Power

### Why Decibels?
Radio deals with huge power ratios. Decibels compress the scale logarithmically.

```
dB = 10 × log₁₀(P₁/P₂)
dBm = 10 × log₁₀(P_watts/0.001W)
```

### Key dB Values (Memorize These!)
```
+3 dB = double power (2×)
+6 dB = 4× power
+10 dB = 10× power
+20 dB = 100× power
+30 dB = 1000× power

-3 dB = half power (50%)
-6 dB = quarter power (25%)  
-10 dB = 1/10 power (10%)
-20 dB = 1/100 power (1%)
```

### Power Reference Scales
```
dBm = decibels relative to 1 milliwatt
0 dBm = 1 mW
+30 dBm = 1 W
+40 dBm = 10 W
+50 dBm = 100 W

dBW = decibels relative to 1 watt
0 dBW = 1 W = +30 dBm
```

### Quick Power Conversions
```
Power (W)    dBm     dBW
1 mW         0       -30
10 mW        +10     -20
100 mW       +20     -10  
1 W          +30     0
10 W         +40     +10
100 W        +50     +20
1 kW         +60     +30
```

### dB Math Shortcuts
```
Adding powers: Add dB values
P_total = P₁ + P₂ → dB_total = dB₁ + dB₂ (when P₁ >> P₂)

Cascaded gains/losses:
dB_total = dB₁ + dB₂ + dB₃ + ...

Example: +20dB amp → 3dB cable loss → +10dB amp
Total gain = 20 - 3 + 10 = +27dB
```

## Basic Components

### Antennas
**Function**: Convert electrical energy ↔ electromagnetic waves

**Types:**
```
Dipole (λ/2):     Omnidirectional, 2.1 dBi gain
Monopole (λ/4):   Ground plane required, 2.1 dBi
Yagi:             Directional, 6-20 dBi gain
Parabolic:        Highly directional, 20-60 dBi
Loop:             Circular polarization, 3 dBi
Patch:            Planar, 6-9 dBi gain
```

**Antenna Gain (dBi vs dBd):**
```
dBi = gain over isotropic radiator
dBd = gain over dipole
dBi = dBd + 2.15
```

### Transmission Lines

**Coaxial Cable:**
```
Type        Impedance    Loss (dB/100ft @ 1GHz)    Use
RG-58       50Ω          40                        Short runs
RG-8        50Ω          15                        High power
RG-6        75Ω          20                        Cable TV
LMR-400     50Ω          7                         Base stations
```

**Key Parameters:**
- Characteristic impedance (Z₀): 50Ω or 75Ω
- Velocity factor (VF): 0.66-0.85 typical
- Loss increases with frequency

### Connectors
```
Connector    Impedance    Frequency    Use
BNC          50Ω          4 GHz        Test equipment
SMA          50Ω          18 GHz       PCB connections  
N-type       50Ω          11 GHz       Base stations
F-type       75Ω          1 GHz        Cable TV
UHF (PL-259) 50Ω          300 MHz      Amateur radio
```

### Basic Circuits

**Resonant Circuit (LC):**
```
f₀ = 1/(2π√LC)

At resonance:
- Series LC: minimum impedance
- Parallel LC: maximum impedance
- Q = quality factor = f₀/bandwidth
```

**Matching Networks:**
```
L-network: Two components (L + C)
Pi-network: Three components (C-L-C)  
T-network: Three components (L-C-L)

Purpose: Transform impedances for maximum power transfer
```

## Signal Quality Metrics

### Signal-to-Noise Ratio (SNR)
```
SNR = 10 × log₁₀(P_signal/P_noise)

Good SNR values:
Voice: >12 dB
Digital: >10 dB  
High-speed data: >20 dB
```

### Sensitivity
Minimum signal level receiver can detect:
```
Thermal noise floor = -174 dBm/Hz @ 290K
P_noise = -174 + 10×log₁₀(BW) + NF

Typical receiver sensitivities:
FM radio: -110 dBm
WiFi: -95 dBm
Cellular: -120 dBm
GPS: -160 dBm
```

### Bit Error Rate (BER)
Digital communication quality metric:
```
BER = errors/total_bits

Acceptable BER:
Voice: 10⁻³ (1 error per 1000 bits)
Data: 10⁻⁶ (1 error per million bits)
Critical systems: 10⁻⁹ or better
```

### Dynamic Range
Ratio between strongest and weakest signals:
```
Dynamic Range = P_max - Sensitivity

Example: P_max = +10 dBm, Sensitivity = -110 dBm
Dynamic Range = 120 dB
```

### Spurious Free Dynamic Range (SFDR)
```
SFDR = (P_signal - P_spur)/2

Measures receiver's ability to handle strong signals
without generating false responses
```

## Frequency Allocations & Regulations

### ISM Bands (License-free)
```
Frequency       Region      Power Limit    Applications
13.56 MHz       Global      ~1W            RFID, diathermy
27 MHz          Most        ~1W            RC toys, CB
40.68 MHz       Some        Low            RC, medical
433-434 MHz     Region 1    10mW           IoT, remote control
902-928 MHz     Region 2    1W             ISM, RFID
2400-2500 MHz   Global      100mW-4W       WiFi, Bluetooth, microwave
5725-5875 MHz   Global      1W             WiFi, radar
24-24.25 GHz    Global      100mW          Motion sensors
61-61.5 GHz     Some        100mW          Short-range comms
```

### Amateur Radio Bands (Examples)
```
Band        Frequency       Wavelength    Characteristics
80m         3.5-4.0 MHz     80m          Regional, noise
40m         7.0-7.3 MHz     40m          Regional/DX, reliable  
20m         14.0-14.35 MHz  20m          Worldwide, DX
15m         21.0-21.45 MHz  15m          DX when open
10m         28-29.7 MHz     10m          Sporadic E, local
6m          50-54 MHz       6m           Sporadic E, tropo
2m          144-148 MHz     2m           Line of sight, repeaters
70cm        420-450 MHz     70cm         Line of sight, urban
```

### Commercial Allocations
```
Service         Frequency       Notes
AM Broadcast    530-1700 kHz    MF propagation
FM Broadcast    88-108 MHz      VHF, line of sight
TV VHF          54-88, 174-216  Channels 2-6, 7-13
TV UHF          470-806 MHz     Channels 14-69
Cellular        800, 900, 1800, Regional variations
                1900, 2100 MHz  
WiFi 2.4 GHz    2400-2484 MHz   Global ISM
WiFi 5 GHz      5150-5825 MHz   Regional variations
Bluetooth       2400-2484 MHz   Frequency hopping
GPS L1          1575.42 MHz     Civil GPS
```

## Basic Calculations & Formulas

### Link Budget
```
P_rx = P_tx + G_tx - L_tx - L_path - L_rx + G_rx

Where:
P_rx = received power (dBm)
P_tx = transmit power (dBm) 
G_tx = transmit antenna gain (dBi)
L_tx = transmit line losses (dB)
L_path = path loss (dB)
L_rx = receive line losses (dB)
G_rx = receive antenna gain (dBi)
```

### Free Space Path Loss
```
L_path = 32.45 + 20×log₁₀(f_MHz) + 20×log₁₀(d_km)

Example: 1 km at 2400 MHz
L_path = 32.45 + 20×log₁₀(2400) + 20×log₁₀(1)
       = 32.45 + 67.6 + 0 = 100 dB
```

### Antenna Basics
```
Effective Radiated Power (ERP):
ERP = P_tx × G_antenna

Effective Isotropic Radiated Power (EIRP):  
EIRP = P_tx × G_antenna (referenced to isotropic)

Antenna efficiency:
η = P_radiated/P_input (typically 50-95%)
```

### Resonance & Bandwidth
```
Resonant frequency: f₀ = 1/(2π√LC)
Bandwidth: BW = f₀/Q
Q factor: Q = X_L/R = 2π×f₀×L/R

Higher Q = narrower bandwidth, more selective
Lower Q = wider bandwidth, less selective
```

---

**End of Stage 1: Radio Fundamentals**

*This stage covered the essential foundation concepts. Next stages will build on these fundamentals to explore modulation, transmission systems, antennas, and practical applications.*

**Prerequisites for Stage 2:** Understanding of dB calculations, basic wave properties, frequency relationships, and component functions.

**Estimated completion time:** 4-6 hours of focused study with hands-on calculator practice.

---

# Stage 2: Modulation & Transmission

## Why Modulation?

### The Problem
You can't transmit baseband signals efficiently:
- Audio (20 Hz - 20 kHz) needs massive antennas
- Digital data has wide spectrum
- Multiple signals would interfere

### The Solution: Modulation
Move information onto a higher frequency carrier:

```
Information signal: 0-4 kHz (voice)
Carrier frequency: 100 MHz (FM radio)
Result: Voice transmitted at 100 MHz ± 75 kHz
```

**Benefits:**
- Efficient antennas (λ/4 practical size)
- Frequency division (many signals, different carriers)
- Better propagation characteristics
- Improved noise immunity

### Modulation Parameters
```
Carrier: A×cos(2πf_c×t + φ)

Amplitude (A): Strength
Frequency (f_c): Center frequency  
Phase (φ): Time reference

Any can carry information!
```

## Analog Modulation

### Amplitude Modulation (AM)
**Concept:** Vary carrier amplitude with information

```
s(t) = [A_c + m(t)] × cos(2πf_c×t)

Where:
A_c = carrier amplitude
m(t) = modulating signal
Modulation index: μ = A_m/A_c
```

**AM Spectrum:**
```
Carrier: f_c
Lower Sideband (LSB): f_c - f_m  
Upper Sideband (USB): f_c + f_m
Bandwidth = 2 × f_m
```

**AM Types:**
```
DSB-FC (Double Sideband Full Carrier):
- Standard AM broadcast
- Inefficient (2/3 power in carrier)
- Simple demodulation

DSB-SC (Double Sideband Suppressed Carrier):
- No carrier transmitted
- More efficient
- Needs carrier recovery

SSB (Single Sideband):
- Transmit only USB or LSB
- Half the bandwidth
- Maximum efficiency
- Used in HF radio
```

**AM Demodulation:**
```
Envelope Detector (DSB-FC):
Diode + RC filter extracts envelope

Synchronous Detection (DSB-SC/SSB):
Multiply by local carrier
Low-pass filter extracts baseband
```

### Frequency Modulation (FM)
**Concept:** Vary carrier frequency with information

```
s(t) = A_c × cos(2πf_c×t + 2πk_f∫m(τ)dτ)

Instantaneous frequency:
f_i(t) = f_c + k_f×m(t)

Frequency deviation: Δf = k_f×A_m
Modulation index: β = Δf/f_m
```

**FM Bandwidth (Carson's Rule):**
```
BW = 2(Δf + f_m) = 2f_m(β + 1)

Examples:
Narrowband FM (NBFM): β < 0.5, BW ≈ 2f_m
Wideband FM (WBFM): β > 1, BW ≈ 2Δf

FM Broadcast: Δf = 75 kHz, f_m = 15 kHz
BW = 2(75 + 15) = 180 kHz → 200 kHz channels
```

**FM Advantages:**
- Excellent noise immunity
- Constant envelope (efficient amplifiers)
- Capture effect (strong signal suppresses weak)

**FM Demodulation:**
```
Frequency Discriminator:
Convert frequency → amplitude
Then envelope detect

PLL (Phase Locked Loop):
Track frequency changes
VCO control voltage = demodulated signal
```

### Phase Modulation (PM)
**Concept:** Vary carrier phase with information

```
s(t) = A_c × cos(2πf_c×t + k_p×m(t))

Relationship to FM:
PM of m(t) = FM of dm(t)/dt
FM of m(t) = PM of ∫m(t)dt
```

**Practical Note:** FM and PM very similar - often used interchangeably in analysis.

## Digital Modulation

### Amplitude Shift Keying (ASK)
**Concept:** Digital version of AM

```
Binary ASK (OOK - On-Off Keying):
'1' = A×cos(2πf_c×t)
'0' = 0

M-ary ASK:
Multiple amplitude levels
```

**Performance:**
- Simple implementation
- Poor noise performance
- Used in fiber optics (OOK)

### Frequency Shift Keying (FSK)
**Concept:** Different frequencies for different bits

```
Binary FSK:
'1' = cos(2πf_1×t)  
'0' = cos(2πf_2×t)

Frequency separation: Δf = |f_1 - f_2|
```

**FSK Types:**
```
Coherent FSK: Synchronized demodulation
Non-coherent FSK: Envelope detection
MSK (Minimum Shift Keying): Δf = R_b/4 (optimal)
```

**Applications:**
- 1200 baud modems
- RFID systems  
- LoRa (Chirp Spread Spectrum variant)

### Phase Shift Keying (PSK)
**Concept:** Different phases for different data

```
Binary PSK (BPSK):
'1' = A×cos(2πf_c×t)     [0°]
'0' = A×cos(2πf_c×t+π)   [180°]

QPSK (Quadrature PSK):
'00' = A×cos(2πf_c×t)         [0°]
'01' = A×cos(2πf_c×t+π/2)     [90°]  
'11' = A×cos(2πf_c×t+π)       [180°]
'10' = A×cos(2πf_c×t+3π/2)    [270°]
```

**Constellation Diagrams:**
```
BPSK: 2 points on real axis
QPSK: 4 points in square pattern
8-PSK: 8 points in circle
16-QAM: 16 points in grid
```

**Performance Comparison:**
```
Modulation    Bits/Symbol    BER @ 10 dB SNR
BPSK          1              10⁻⁵
QPSK          2              10⁻⁵  
8-PSK         3              10⁻³
16-QAM        4              10⁻³
64-QAM        6              10⁻²
```

### Quadrature Amplitude Modulation (QAM)
**Concept:** Combine amplitude and phase modulation

```
s(t) = I(t)×cos(2πf_c×t) - Q(t)×sin(2πf_c×t)

I(t) = In-phase component
Q(t) = Quadrature component
```

**QAM Constellations:**
```
4-QAM = QPSK: 4 points, 2 bits/symbol
16-QAM: 16 points, 4 bits/symbol  
64-QAM: 64 points, 6 bits/symbol
256-QAM: 256 points, 8 bits/symbol
```

**Applications:**
- Cable modems (64/256-QAM)
- WiFi (16/64/256-QAM)
- Cellular (16/64/256-QAM)

## Spread Spectrum

### Why Spread Spectrum?
**Benefits:**
- Security (hard to intercept)
- Interference rejection
- Multiple access capability
- Low probability of detection

### Direct Sequence Spread Spectrum (DSSS)
**Concept:** Multiply data with fast pseudo-random code

```
Transmitted signal = Data × PN_code × Carrier
Chip rate >> Bit rate
Processing gain = Chip_rate/Bit_rate
```

**Example:**
```
Data bit: '1' (1 ms duration)
PN code: 1011 0110 1001... (1 MHz chip rate)
Result: 1000 chips per data bit
Processing gain = 1000 = 30 dB
```

**DSSS Reception:**
1. Correlate with same PN code
2. Narrow interference spreads out
3. Spread signal despreads
4. SNR improves by processing gain

**Applications:**
- GPS (C/A code: 1023 chips)
- 802.11b WiFi (Barker sequence)
- CDMA cellular

### Frequency Hopping Spread Spectrum (FHSS)
**Concept:** Rapidly change carrier frequency according to PN sequence

```
Hop rate: Frequency changes per second
Dwell time: Time spent on each frequency
Hopping bandwidth: Total frequency range
```

**FHSS Types:**
```
Fast Hopping: Multiple hops per symbol
Slow Hopping: Multiple symbols per hop

Example (Bluetooth):
79 frequencies (2402-2480 MHz)  
1600 hops/second
625 μs dwell time
```

**Benefits:**
- Interference hits only some hops
- Natural frequency diversity
- Simple implementation

### Chirp Spread Spectrum (CSS)
**Concept:** Continuously vary frequency over time

```
Linear chirp: f(t) = f_0 + k×t
k = (f_1 - f_0)/T

Used in:
- LoRa (LoRaWAN)
- Radar systems
- Ultrasonic ranging
```

## Multiple Access

### Frequency Division Multiple Access (FDMA)
**Concept:** Different users get different frequencies

```
User 1: f_1 ± BW/2
User 2: f_2 ± BW/2  
User 3: f_3 ± BW/2
Guard bands prevent interference
```

**Examples:**
- FM radio stations
- Analog cellular (AMPS)
- Satellite transponders

### Time Division Multiple Access (TDMA)
**Concept:** Different users get different time slots

```
Frame structure:
|Slot 1|Slot 2|Slot 3|Slot 4|Slot 1|...
User A gets Slot 1 every frame
User B gets Slot 2 every frame
Synchronization critical
```

**Examples:**
- GSM cellular
- Digital cordless phones
- Satellite systems

### Code Division Multiple Access (CDMA)
**Concept:** Different users get different codes

```
All users transmit simultaneously
Same frequency, same time
Separated by orthogonal codes
DSSS implementation

User signals:
S_1(t) = D_1(t) × C_1(t) × cos(2πf_c×t)
S_2(t) = D_2(t) × C_2(t) × cos(2πf_c×t)

Received: S_1(t) + S_2(t) + noise
Demodulate User 1: Correlate with C_1(t)
```

**Advantages:**
- Soft capacity limit
- Graceful degradation
- Inherent diversity
- Security

**Applications:**
- IS-95/CDMA2000 cellular
- UMTS/WCDMA
- GPS satellites

### Orthogonal Frequency Division Multiple Access (OFDMA)
**Concept:** Multiple users share orthogonal subcarriers

```
OFDM: Multiple parallel subcarriers
Orthogonal: No inter-carrier interference
Each subcarrier can use different modulation

User allocation:
User A: Subcarriers 1,5,9,13...
User B: Subcarriers 2,6,10,14...
User C: Subcarriers 3,7,11,15...
```

**Benefits:**
- Frequency selective scheduling
- Efficient spectrum use
- Good multipath performance

**Applications:**
- LTE cellular
- WiMAX
- WiFi 6 (802.11ax)

## Transmitter Design

### Basic Transmitter Architecture

**Direct Conversion (Zero-IF):**
```
Baseband I/Q → Mixer → PA → Antenna
                ↑
              LO (f_c)

Advantages: Simple, cheap
Disadvantages: LO leakage, I/Q imbalance
```

**Superheterodyne:**
```
Baseband → IF → Mixer → PA → Antenna
            ↑     ↑
           f_IF   LO

Better image rejection
More complex but cleaner output
```

### Key Transmitter Blocks

**Digital-to-Analog Converter (DAC):**
```
Resolution: 8-16 bits typical
Sample rate: >2× signal bandwidth
SNR ≈ 6×N + 1.76 dB (N = bits)
```

**Mixers:**
```
Convert frequency: f_out = f_LO ± f_in
Spurious products: m×f_LO ± n×f_in
Image frequency: f_image = f_LO - f_desired
```

**Power Amplifier (PA):**
```
Classes:
A: Linear, 50% efficiency max
B: Push-pull, 78% efficiency max  
C: Switched, >85% efficiency, nonlinear
D/E/F: Switched mode, >90% efficiency

Linearity vs Efficiency tradeoff
```

**Filtering:**
```
Anti-aliasing: Before ADC
Image reject: After mixer
Harmonic: After PA
Spurious: Multiple locations
```

### Transmitter Specifications

**Output Power:**
```
Handheld: 1-5W
Mobile: 10-50W  
Base station: 10-1000W
Broadcast: 1-500 kW
```

**Efficiency:**
```
η = P_RF / P_DC

Typical values:
Cellular handset: 25-40%
Base station: 40-60%
FM broadcast: 70-85%
```

**Spurious Emissions:**
```
In-band: <-40 dBc
Out-of-band: <-60 dBc
Harmonics: <-40 dBc (varies by band)
```

**Modulation Accuracy:**
```
EVM (Error Vector Magnitude):
Digital modulation quality metric
<5% typical for cellular
<1% for high-order QAM
```

## Receiver Design

### Receiver Architectures

**Superheterodyne (Superhet):**
```
Antenna → RF Filter → LNA → Mixer → IF Filter → Demod
                              ↑
                             LO₁

Classical architecture, excellent performance
Multiple IF stages possible
```

**Direct Conversion (Homodyne):**
```
Antenna → RF Filter → LNA → I/Q Mixers → Baseband
                              ↑
                          LO (f_c)

Simple, low cost
DC offset and flicker noise issues
```

**Low-IF:**
```
Single conversion to low IF (few MHz)
Digital demodulation
Compromise between superhet and direct conversion
```

### Key Receiver Blocks

**Low Noise Amplifier (LNA):**
```
First active stage - sets noise figure
Noise Figure: 0.5-3 dB typical
Gain: 10-20 dB
Must not overload (good linearity)
```

**Mixers:**
```
Conversion gain/loss: 0 to +10 dB
Noise figure: 6-12 dB
IP3 (third-order intercept): +10 to +25 dBm
```

**Intermediate Frequency (IF):**
```
First IF: 70 MHz, 455 kHz (AM/FM)
Second IF: 455 kHz, 10.7 MHz
Modern: 0-50 MHz range
```

**Automatic Gain Control (AGC):**
```
Maintains constant signal level
Dynamic range: 60-100 dB
Time constants: ms to seconds
Prevents overload/distortion
```

### Receiver Specifications

**Sensitivity:**
```
Minimum detectable signal
Depends on:
- Noise figure
- Bandwidth  
- Required SNR

P_min = -174 + 10×log(BW) + NF + SNR_req

Example: NF=3dB, BW=200kHz, SNR=10dB
P_min = -174 + 53 + 3 + 10 = -108 dBm
```

**Selectivity:**
```
Adjacent channel rejection: >60 dB
Alternate channel rejection: >80 dB
Image rejection: >60 dB
IF rejection: >80 dB
```

**Dynamic Range:**
```
Spurious Free Dynamic Range (SFDR):
Range between noise floor and spurious products

Typical: 70-100 dB
Limited by ADC in digital receivers
```

**Phase Noise:**
```
LO phase noise affects:
- Reciprocal mixing
- EVM degradation
- Adjacent channel interference

Typical: -100 dBc/Hz @ 10 kHz offset
```

### Software Defined Radio (SDR)

**Concept:** Move signal processing to digital domain

```
Traditional: Fixed hardware filtering/demodulation
SDR: Digitize early, process in software

Advantages:
- Reconfigurable
- Multiple standards
- Easy updates
- Reduced hardware
```

**SDR Architecture:**
```
Antenna → RF Filter → LNA → ADC → FPGA/DSP
                              ↓
                         Digital Processing:
                         - Filtering
                         - Demodulation  
                         - Decoding
```

**Popular SDR Platforms:**
```
RTL-SDR: $20, RX only, 24-1766 MHz
HackRF: $300, TX/RX, 1-6000 MHz  
BladeRF: $400, TX/RX, 300-3800 MHz
USRP: $1000+, Professional, wide range
```

---

**End of Stage 2: Modulation & Transmission**

*This stage covered modulation techniques from basic AM/FM to advanced digital schemes, spread spectrum methods, multiple access techniques, and transmitter/receiver design principles.*

**Prerequisites for Stage 3:** Understanding of modulation concepts, frequency domain analysis, and basic RF circuit knowledge.

**Estimated completion time:** 6-8 hours of study with simulation/SDR experiments.

---

# Stage 3: Antennas & Propagation

## Antenna Fundamentals

### What is an Antenna?
A transducer that converts:
- **Transmit:** Electrical energy → Electromagnetic waves
- **Receive:** Electromagnetic waves → Electrical energy

**Reciprocity:** Transmit and receive properties are identical

### Key Antenna Parameters

**Radiation Pattern:**
```
3D plot showing directional radiation
Usually shown as 2D cuts:
- E-plane (electric field plane)
- H-plane (magnetic field plane)

Types:
- Omnidirectional: Equal radiation all directions
- Directional: Focused in specific direction
- Isotropic: Theoretical point source (reference)
```

**Gain:**
```
G = Directivity × Efficiency

Directivity (D): Concentration of power
Efficiency (η): Power radiated / Power input

Units:
dBi = dB relative to isotropic radiator
dBd = dB relative to dipole
dBi = dBd + 2.15
```

**Beamwidth:**
```
Half-Power Beamwidth (HPBW):
Angle between -3dB points

First Null Beamwidth (FNBW):
Angle between first nulls

Typical relationships:
Higher gain → Narrower beamwidth
G ≈ 41,253 / (θ_E × θ_H)
where θ_E, θ_H in degrees
```

**Input Impedance:**
```
Z_in = R_in + jX_in

For maximum power transfer:
Z_antenna = Z_line*

Typical values:
50Ω (most systems)
75Ω (cable TV, some broadcast)
377Ω (free space impedance)
```

**Bandwidth:**
```
Frequency range where antenna meets specs
Usually defined by:
- VSWR < 2:1 (return loss > 10dB)
- Gain variation < 3dB
- Pattern distortion acceptable

Types:
Narrowband: 1-5%
Wideband: 10-50%  
Broadband: >50%
Ultra-wideband: >100%
```

### Fundamental Limits

**Physical Size vs Frequency:**
```
Minimum effective size ≈ λ/10
Practical size ≈ λ/4 to λ/2
Gain increases with electrical size

Wheeler's formula (small antennas):
Efficiency drops rapidly below λ/10
```

**Gain-Beamwidth Product:**
```
G × Ω = 4π
where Ω = solid angle (steradians)

Cannot increase gain without narrowing beam
Conservation of energy principle
```

## Antenna Types

### Wire Antennas

**Monopole (λ/4):**
```
Length: λ/4
Ground plane required
Input impedance: 36.5Ω
Gain: 2.15 dBi (over isotropic)
Radiation pattern: Omnidirectional (horizontal)

Applications:
- Vehicle antennas
- Base station verticals
- Handheld radios
```

**Dipole (λ/2):**
```
Length: λ/2 total (λ/4 each element)
No ground plane needed
Input impedance: 73Ω
Gain: 2.15 dBi
Radiation pattern: Figure-8 (broadside)

Feed point variations:
Center-fed: Standard dipole
Off-center: Wideband characteristics
End-fed: High impedance matching needed
```

**Loop Antennas:**
```
Small loop (circumference << λ):
- Magnetic field antenna
- Low radiation resistance
- High Q (narrow bandwidth)
- Directional (figure-8)

Large loop (circumference ≈ λ):
- Resonant structure
- Higher efficiency
- Omnidirectional (when horizontal)
```

**Yagi-Uda:**
```
Elements:
- Driven element (λ/2 dipole)
- Reflector (slightly longer, behind)
- Directors (slightly shorter, front)

Characteristics:
Forward gain: 6-20 dBi
Front-to-back ratio: 15-25 dB
Beamwidth: 30-70 degrees
Length: 2-10 wavelengths

Design rules:
Reflector: 5% longer than driven element
Directors: 4% shorter (progressively)
Spacing: 0.15-0.25λ typical
```

### Aperture Antennas

**Horn Antennas:**
```
Rectangular horn:
- E-plane flare (electric field direction)
- H-plane flare (magnetic field direction)
- Gain ≈ 10×log(A_eff/λ²)

Pyramidal horn:
- Both planes flare
- Higher gain
- More symmetric pattern

Typical gains: 10-25 dBi
Applications: Feeds, test antennas, radar
```

**Reflector Antennas:**
```
Parabolic reflector:
- Focus plane waves to point (RX)
- Convert point source to plane waves (TX)
- Gain = η × (πD/λ)²
- Efficiency η = 0.6-0.8 typical

Cassegrain:
- Sub-reflector reduces feed blockage
- Longer effective focal length
- Better pattern control

Offset-fed:
- No feed blockage
- Higher efficiency
- Asymmetric pattern
```

**Patch/Microstrip Antennas:**
```
Structure:
Ground plane + dielectric + metal patch

Advantages:
- Low profile
- Light weight  
- Easy fabrication
- Array integration

Disadvantages:
- Narrow bandwidth (2-5%)
- Lower efficiency
- Surface wave losses

Typical specs:
Gain: 5-9 dBi
Bandwidth: 1-3%
Efficiency: 70-90%
```

### Array Antennas

**Linear Arrays:**
```
N elements in line
Element spacing: typically 0.5λ
Phase progression between elements

Uniform array:
- All elements identical amplitude
- Linear phase progression
- Main beam steerable

Beam steering:
θ = arcsin(cβ/2πd)
where β = phase difference, d = spacing
```

**Planar Arrays:**
```
2D arrangement of elements
Independent control of both planes
Higher gain potential
More complex feeding

Typical configurations:
- Rectangular grid
- Triangular lattice
- Circular arrays
```

### Specialized Antennas

**Helical Antenna:**
```
Wire wound in helix shape
Axial mode: Circular polarization
Normal mode: Linear polarization

Axial mode specs:
Gain: 10-15 dBi
Axial ratio: <3 dB
Bandwidth: 50-100%

Applications:
- Satellite communication
- RFID readers
- GPS antennas
```

**Log-Periodic:**
```
Self-scaling structure
Broadband characteristics
Moderate gain across band

Frequency range: 10:1 typical
Gain: 6-10 dBi
Applications: EMI testing, wideband comms
```

**Fractal Antennas:**
```
Self-similar structures
Multi-band resonances
Compact size

Examples:
- Sierpinski gasket
- Koch snowflake
- Hilbert curve

Applications: Multi-band mobile devices
```

## Antenna Arrays

### Array Theory

**Array Factor:**
```
AF = Σ I_n × e^(jψ_n)
where ψ_n = k×d×cos(θ) + α_n

I_n = element current amplitude
α_n = element phase
d = element spacing
θ = observation angle
```

**Pattern Multiplication:**
```
Array Pattern = Element Pattern × Array Factor

Allows separate design of:
1. Element characteristics
2. Array directivity
```

### Uniform Linear Arrays

**Broadside Array:**
```
All elements in phase (α = 0)
Maximum radiation perpendicular to array
Beam width ≈ 51λ/(N×d) degrees

N = number of elements
d = spacing (wavelengths)
```

**End-fire Array:**
```
Progressive phase shift: α = -kd
Maximum radiation along array axis
Higher directivity than broadside
Beam width ≈ 102λ/(N×d) degrees
```

**Beam Steering:**
```
Steer angle θ_0:
α = kd×cos(θ_0)

Electronic steering:
Change phase electronically
No mechanical movement
Fast switching capability
```

### Array Synthesis

**Dolph-Chebyshev:**
```
Optimum sidelobe level
Equal sidelobe levels
Narrowest main beam for given sidelobe level

Trade-off:
Lower sidelobes → Wider main beam
```

**Taylor Distribution:**
```
Continuous aperture equivalent
Adjustable sidelobe region
Good compromise design
```

**Adaptive Arrays:**
```
Automatic null steering
Interference suppression
Signal optimization

Applications:
- Radar systems
- Cellular base stations
- GPS anti-jam
```

## Antenna Measurements

### Return Loss/VSWR

**Definitions:**
```
Return Loss (RL) = -20×log|Γ|
VSWR = (1 + |Γ|)/(1 - |Γ|)
Γ = reflection coefficient

Good values:
RL > 10 dB (VSWR < 2:1)
RL > 15 dB (VSWR < 1.4:1)
RL > 20 dB (VSWR < 1.2:1)
```

**Measurement Setup:**
```
Vector Network Analyzer (VNA)
Calibration essential:
- Open
- Short  
- Load (50Ω)

S11 measurement = reflection coefficient
```

### Radiation Pattern

**Anechoic Chamber:**
```
Absorber-lined chamber
Eliminates reflections
Far-field conditions
Expensive but accurate

Pattern cuts:
- Azimuth (horizontal)
- Elevation (vertical)
- Principal planes
```

**Near-Field Scanning:**
```
Measure close to antenna
Transform to far-field mathematically
Compact test setup
Good for large antennas

Scanning types:
- Planar (flat surface)
- Cylindrical
- Spherical
```

**Outdoor Range:**
```
Far-field measurement
Large separation distances
Ground reflection issues
Weather dependent

Elevated range:
Reduce ground effects
Height > 2D²/λ
D = antenna dimension
```

### Gain Measurement

**Gain Transfer:**
```
Compare to known reference antenna
Same measurement setup
Account for path loss
Requires calibrated standard

G_test = G_ref + P_test - P_ref
```

**Three-Antenna Method:**
```
Measure three antenna combinations
Calculate gain without standard
More complex but self-contained
Good for establishing standards
```

## Propagation Mechanisms

### Free Space Propagation

**Characteristics:**
```
Line-of-sight path
No obstructions
Spherical wave spreading
Frequency independent (dB)

Path Loss:
L_fs = 32.45 + 20×log(f_MHz) + 20×log(d_km)

Example: 1 GHz, 10 km
L_fs = 32.45 + 60 + 20 = 112.45 dB
```

**Fresnel Zones:**
```
Ellipsoidal zones between TX/RX
First Fresnel zone most important
60% clearance usually sufficient

Radius: r₁ = √(λd₁d₂/(d₁+d₂))
d₁, d₂ = distances from obstacle
```

### Ground Wave Propagation

**Surface Wave:**
```
Follows earth's curvature
Vertically polarized
Frequency dependent attenuation
Range decreases with frequency

LF/MF bands (30 kHz - 3 MHz)
Range: 100-1000 km
Applications: AM broadcast, navigation
```

**Ground Reflection:**
```
Direct + reflected ray
Path difference causes interference
Null zones possible

Two-ray model:
Grazing angle effects
Ground conductivity/permittivity
Polarization effects
```

### Ionospheric Propagation

**Ionosphere Layers:**
```
D layer: 60-90 km (absorption)
E layer: 90-130 km (some reflection)
F₁ layer: 130-210 km (daytime)
F₂ layer: 210-400 km (main reflector)

Ionization varies:
- Time of day
- Season
- Solar activity
- Geographic location
```

**Skip Propagation:**
```
HF frequencies (3-30 MHz)
Signal reflects off ionosphere
Enables worldwide communication
Skip distance varies with:
- Frequency
- Time of day
- Solar conditions

Maximum Usable Frequency (MUF)
Lowest Usable Frequency (LUF)
```

**Critical Frequency:**
```
f_c = 9√(N_e)
N_e = electron density

Vertical incidence limit
Higher frequencies penetrate
Lower frequencies reflect
```

### Tropospheric Propagation

**Standard Propagation:**
```
VHF/UHF frequencies
Slight bending due to atmosphere
Range slightly beyond horizon

Radio horizon:
d_km = 4.12×(√h₁ + √h₂)
h in meters above ground
```

**Anomalous Propagation:**
```
Ducting: Trapped energy
Temperature/humidity inversions
Extended range possible
Can cause interference

Types:
- Surface ducts
- Elevated ducts
- Troposcatter
```

**Rain Attenuation:**
```
Significant above 10 GHz
Raindrop scattering/absorption
Path length through rain matters

Approximate values:
10 GHz: 0.1 dB/km in heavy rain
20 GHz: 0.5 dB/km in heavy rain
40 GHz: 2 dB/km in heavy rain
```

## Path Loss Models

### Empirical Models

**Friis Free Space:**
```
L_fs = (4πd/λ)²
In dB: L_fs = 32.45 + 20×log(f_MHz) + 20×log(d_km)

Valid for:
- Line of sight
- Far field (d > 2D²/λ)
- No obstructions
```

**Plane Earth (Two-Ray):**
```
Beyond breakpoint distance:
L = 40×log(d) - 20×log(h_t) - 20×log(h_r)

h_t, h_r = antenna heights
Valid for d > 4×h_t×h_r/λ
```

**Hata Model (Urban):**
```
L = 69.55 + 26.16×log(f_MHz) - 13.82×log(h_base)
    - a(h_mobile) + (44.9 - 6.55×log(h_base))×log(d_km)

Valid:
150-1500 MHz
1-20 km range
Urban environments
```

**COST 231 Extension:**
```
Extends Hata to 2 GHz
Urban/suburban variants
DCS-1800, GSM-1900 applications

Correction factors:
Dense urban: +3 dB
Suburban: -2×[log(f/28)]² - 5.4 dB
```

### Specific Environment Models

**Indoor Propagation:**
```
Log-distance model:
L = L₀ + 10n×log(d/d₀) + X_σ

Typical path loss exponents:
Free space: n = 2
Office: n = 2.5-3.5
Dense building: n = 4-6

Floor loss: 10-20 dB per floor
Wall loss: 3-10 dB per wall
```

**Vegetation Loss:**
```
ITU vegetation model:
L_veg = 0.2×f^0.3×d^0.6

f in MHz, d in meters
Valid for 30-60 GHz
Single vegetation path

Multiple trees:
Use effective depth method
Account for tree density
```

**Building Penetration:**
```
Frequency dependent
Material dependent
Incident angle effects

Typical values:
Wood frame: 5-10 dB
Concrete block: 10-20 dB
Steel/concrete: 20-30 dB
Metallized glass: 20-40 dB
```

## Fading & Multipath

### Types of Fading

**Large-Scale Fading:**
```
Path loss variations over large distances
Caused by:
- Distance changes
- Shadowing by large objects
- Terrain variations

Statistics: Log-normal distribution
Standard deviation: 6-12 dB typical
```

**Small-Scale Fading:**
```
Rapid variations over short distances
Caused by multipath propagation
Scale: λ/2 distance variations

Types:
- Flat fading (frequency non-selective)
- Frequency selective fading
```

### Multipath Channel Models

**Two-Ray Model:**
```
Direct ray + one reflected ray
Simple but captures basics
Phase relationship critical

Received power variations:
Constructive: signals add
Destructive: signals cancel
Deep nulls possible
```

**Rayleigh Fading:**
```
No dominant path (NLOS)
Amplitude follows Rayleigh distribution
Phase uniformly distributed

PDF: p(r) = (r/σ²)×exp(-r²/2σ²)
Used for: Urban mobile, indoor
```

**Rician Fading:**
```
One dominant path + scattered paths
Amplitude follows Rician distribution
K-factor: ratio dominant/scattered power

K = 0: Rayleigh fading
K → ∞: No fading (AWGN)
Typical K: 5-15 dB (suburban)
```

**Nakagami Fading:**
```
Generalized fading model
Shape parameter m controls severity
m = 1: Rayleigh
m = ∞: No fading

More flexible than Rician
Good fit to measurements
```

### Diversity Techniques

**Space Diversity:**
```
Multiple antennas separated by >λ/2
Exploits spatial decorrelation
SIMO, MISO, MIMO systems

Combining methods:
- Selection (choose best)
- Maximal ratio (weight by SNR)
- Equal gain (equal weights)
```

**Frequency Diversity:**
```
Transmit on multiple frequencies
Coherence bandwidth separation
Spread spectrum systems
OFDM with coding
```

**Time Diversity:**
```
Repeat transmission
Exploit temporal decorrelation
Interleaving + coding
ARQ (automatic repeat request)
```

**Polarization Diversity:**
```
Use orthogonal polarizations
Cross-polar discrimination
Limited by XPD of channel
Compact antenna implementation
```

### Channel Characterization

**Delay Spread:**
```
RMS delay spread: τ_rms
Measure of multipath spread
Affects symbol rate limits

Coherence bandwidth:
B_c ≈ 1/(5×τ_rms)

For B_signal < B_c: Flat fading
For B_signal > B_c: Frequency selective
```

**Doppler Spread:**
```
Maximum Doppler: f_d = v×f_c/c
Coherence time: T_c ≈ 0.423/f_d

For T_symbol < T_c: Slow fading
For T_symbol > T_c: Fast fading

Mobile at 100 km/h, 2 GHz:
f_d = 185 Hz, T_c = 2.3 ms
```

**Channel Models:**
```
Tapped delay line model:
h(t,τ) = Σ a_n(t)×δ(τ - τ_n)

Each tap: independent fading
Delays: fixed
Amplitudes: time-varying (Rayleigh/Rician)

Standard models:
- ITU vehicular A/B
- ITU pedestrian A/B  
- 3GPP channel models
```

---

**End of Stage 3: Antennas & Propagation**

*This stage covered antenna theory and types, array concepts, measurement techniques, propagation mechanisms, path loss modeling, and multipath/fading characteristics essential for radio system design.*

**Prerequisites for Stage 4:** Understanding of electromagnetic theory, complex numbers, and statistical concepts for fading analysis.

**Estimated completion time:** 8-10 hours of study with antenna modeling and measurement exercises.