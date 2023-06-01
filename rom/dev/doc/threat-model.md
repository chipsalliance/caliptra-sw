# Outline
The documentation’s purpose is to iterate threat that the Caliptra ROM will face from potential attackers, we will also look at the potential mitigations and the difficulty level of the attack. The goal for this document is to look at just the Caliptra ROM and what thread that it can potentially face.  There is a comprehensive [Caliptra Asset & Threats](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#caliptra-assets--threats) writing currently in the Caliptra specification that covers Caliptra IP as a whole. 
The main area of attack surface that we will look at includes the following,
-	ROM Confidentiality / Reverse Engineering Attack
-	Mailbox Interface Attack
-	Physical Attacks (Glitching)
-	DPA/DFA Attacks
-	Oracle Attacks

# ROM Confidentiality / Reverse Engineering Attack

## Attack Description
Usually, the ROM of a silicon’s ROT is considered confidential for many reasons, especially to prevent reverse engineering attempts that can potentially lead to more exploitable vulnerabilities from white box attacks.  Since Caliptra’s soul is an Open-Source Project and the ROM code is available for all to see.  There is no confidentiality in the ROM code at all and we need to consider all types of white box attacks.  Attackers are armed with full knowledge of the ROM code so any logical error might be able to be turned into an exploitable vulnerability.

## Mitigation
Mitigation for this will consist mostly typical code review and analysis methods.
- Rigorous code review 
  - The best defense is to ensure that the ROM code does not have exploitable vulnerability that can be exported.  Code review and finding coding error early on can help reduce vulnerability vectors that might be able to be exported by a malicious actor.
- Proactive static analysis 
  - Static analysis would be a great tool to employe in mitigating this.  Even though Rust does have compile-time error checks, it can still benefit from running rust focused static analysis tools to further reduce potential coding errors.
- ROM Patching
  - ROM Patching is one way to be able to patch the ROM without taping out silicon again if a bug in the masked ROM is found post tapeout.  Currently it is not supported by Caliptra, but it might be something we can consider in the future if the need arises.  ROM Patch does bring other security concern such as measuring and attesting to the ROM patch.

# Mailbox Interface Attacks
## Attack Description
One of the most common attacks that would be done on a secure processor such as Caliptra would be interface based attack on the external interface that is exposed to the external software conduct offensive fuzzing on the interface.  Any unexpected behavior not handled well could become a vector that results in an exploitable situation.  
Mitigation
Multiple mitigation can be done to alleviate such attack.  From enclosing Caliptra interface to another highly trusted entity such as SOC ROT/management process to proactively engaging in dynamic analysis and fuzzing of the ROM interface.
- Enclose Caliptra mailbox interface to SOC management processor.
  - SOC Management processor is usually of a higher trust level compared to application processor (CPU).  By enclosing the Caliptra mailbox interface to such entity, it reduces the attack surface of an attacker gaining the ability to attack Caliptra mailbox.  While this is not something Caliptra ROM can affect.  We can put this as a recommendation for Caliptra integration guidelines. 
- Proactive fuzzing
  - Conduct fuzzing on any Caliptra mailbox interface that the ROM provides.  This includes fuzzing the Caliptra mailbox commands and manipulate the Caliptra firmware image.  This shall be done for both Cold boot and Hitless update boot sequence.  
  - To reduce attack further, if we have decided that warm boot for Caliptra is no longer needed, we should take Warm boot code out of ROM to reduce attack surface.
- Strengthen error handling.
  - Another mitigation to block attacker from doing offensive interface attack is a robust error handling policy.  A fatal or unexpected error can cause Caliptra to go into a turtle like mechanism which can only be solved with a system reset will significantly increase the difficulty for the attacker to fuzz the interface offensively.
- Strong memory property protection
  - Many interface-based attack rely on out of bound access to memory region that should not be executable (stack / data).  By having strong memory property protection (R/W Only, NX), we can ensure that the risk of ROP type of attack can be decreased even if the attacker were able to compromise the interface initially. 

# Physical Attacks (Glitching / Fault Injection)
## Attack Description
Physical attack includes a wild range of attacks that includes but is not limited to the following.
- Voltage / Clock based glitch.
- Thermal attacks
- Electromagnetic fault attack
- Laser attack
While the attack methodology and expertise required differ significantly, the goal of the attack and the observable behavior from the attack can be summarized to be the unexpected behavior of code execution that does not follow the original intended flow.  The effect of a glitch attack is most likely randomized behavior in the system under attack.  The observable behavior that has security concerns can be the following.
- Instruction skipping or modification.
- Data corruption
- Control flow alteration
While the chance of success might be very low for an attacker to randomly attack Caliptra which is a very small IP within a larger silicon.  A more sophisticated attacker will be able to pinpoint the attack more precisely both spatially and temporally.  

## Mitigation
The most effective defense against physical glitch / fault injection attacks would be specialized circuits in HW that would detect or prevent such attacks.  However, from a coding perspective, there are well established glitch mitigation coding mechanics that can help with preventing glitched behavior to turn into an exploitable vulnerability.
- Initialize / Re-initialize status return to error prior to use.
  - By relying on compiler to initialize status registers is not reliable.  It is important to initialize all status registers to failure/error so that if a function call return that would change the status register is skipped or bypassed, the status check would result in error.  
  - It is also essential to re-initialize the status register to failure/error if it were to be used again later in the function for another call.
- Critical path redundancy checks on if/else/switch statements.
  - Majority of the glitch attack target critical path if/else statements where things such as debug enable check, authentication check is done and the test for result is critical to the security assurance of the system.  Running unauthenticated code for escalation of privilege is a known attack that has been demonstrated in multiple instances.  By applying multiple checks (check for failure again in success path for example) can help mitigate most of those attacks.  
- Increase hamming distance.
  - Glitch attack also depend heavily on bit flips.  Typical definition of a Boolean state would easily be switched from true to false with glitch attacks if it is presented with only one bit difference.  By increasing the hamming distance, it would mitigate the single bit flip failures that can be seen from glitches.
  - Hamming distance does not only apply to true/false usage, loop increment and termination condition can also be easily glitched without hamming distance implemented.  
- Randomized Delay
  - Since most successful glitch attack that result to exploitable vulnerability are not done randomly from a timing perspective, it is important to add randomized delay into the cold flow.  For example, the attacker could time off external bus access to storage device, x ms after would likely be the authentication call.  A timed attack with that knowledge is a lot more likely to succeed than a pure random attack.  By adding random delays in the critical path between externally measurable signal to internal critical security function call can mitigate this and make it harder for the attacker. 
- Control flow audit
  - Sometimes a large section of code execution can be skipped through glitching.  Adding counter track to ensure all the critical section is executed can catch and alleviate otherwise undetectable problems like that could have undesirable unknown effect for code executing later in the flow.

# DPA / DFA (Side Channel) Attacks
## Attack Description
DPA (Differential Power Analysis) and DFA (Differential Fault Analysis) attacks are common side-channel attacks targeting cryptographic systems in the secure element.  
- To launch a successful DPA attack on cryptographic system attacker must be able to control input of crypto operation either ciphertext of decryption or plaintext of encryption and measure power consumption of a target device with external means such as oscilloscope.
  - Caliptra's assets that can be attacked with DPA
    - UDS – if attacker is able to feed known IV value through glitching or probing it will allow an attacker to recover decrypted/deobfuscated UDS.
    - RTL key – if attacker able to deterministically glitch UDS seed known cipher text can be fed into deobfuscation engine and RTL key recovered with DPA attack.
- DPA on ECDSA
  - Side-channel on the elliptic curve exploits the fact that the secret scalar value is used one bit at a time in ECDSA point multiplication operation and if recovered can be used to derive private key. Successful attack requires multiple traces where secret scalar remains constant for each trace, but a different point is used for each trace however we don’t need a knowledge on what the point is.
    - Caliptra uses chip-class ECDSA-384 private key provisioned by a vendor to sign device identifier certificate.
- DFA attacks require feeding known plain/ciphertext, glitching cryptographic IP and observing the output of cryptographic operation. While DFA attacks require all 3 previously mentioned conditions, the number of traces required to perform such an attack is in the order of few thousand traces also often times DFA attacks can be performed purely from software if an attacker has ability to control SoC voltage via software interface.


## Mitigation
- IV
  - Treat IV as private and do not expose software interfaces that use IV as an input.
- Crypto IP
  - Use established coutermeasures such as adding dummy rounds, random data masking, timing randomization.

# Caliptra Integration Attacks
## Attack Description
Certain part of Caliptra’s security rely on the correct integration of Caliptra by the SOC Vendors.  For example, it is possible to integrate Caliptra without providing HW FUSE for certain elements and have HW to implement register interface that the SOC Management Processor can write to for pushing FUSE values into Caliptra.  An implementation like this can be invisible to the outside world as Caliptra can be only accessible by the SOC Management Processor.  A successful attack on the SOC Management Processor can also mean the security of the Caliptra is now lost.  
However, Caliptra is within SOC Vendor’s trust boundary as the Caliptra asset (keys, etc) belong to the SOC Vendor.  We can argue that a SOC Vendor attacking on Caliptra through integration would not be in scope of the threat model.  However correct integration should be enforced to lower other risks. 
Strictly from ROM perspective, the risk is the correct integration of the Caliptra ROM without modification.  This is not measured to be attestable, same applies to the RTL implementation of Caliptra overall.

## Mitigation
- Integration guidance
  - By giving detailed integration guidance, we can reduce the problems that might arise during integration.
- Caliptra certification
  - Having a proper certification process to ensure Caliptra integration is done correctly can also mitigate the risk here.