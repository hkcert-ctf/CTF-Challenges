1. # Cruel RSA Analysis and Decryption Process (Writeup)

   This document sorts out the key generation logic, information leakage characteristics of a variant RSA (Cruel RSA) constructed based on Blum primes, as well as the complete cracking process through Lattice Basis Reduction (LLL) and polynomial elimination.

   ## 1. Key Construction Principle

   ### 1.1 Prime and Modulus Generation

   Select a Blum prime g, and arbitrarily choose integers a,b to construct two large primes:

   p=2ga+1,q=2gb+1

   Define the RSA modulus N=pq, and introduce an intermediate parameter:

   L=2gab

   ### 1.2 Public and Private Key Exponent Generation

   - **Private key exponent \**d\**** : A prime number with a specified bit length is selected;

   - Public key exponent **e**

      : Satisfies the inverse element relationship modulo 

     L

     , i.e.,

     

     ed≡1(modL)

   ## 2. Leaked Information and Parametric Representation

   ### 2.1 Leakage Characteristics of Private Key Exponent d

   The **Most Significant Bits (MSB)** and **Least Significant Bits (LSB)** of d are leaked, with the formal definitions:

   dMSB=⌊2k−msd⌋,dLSB=dmod2ls

   where k is the total bit length of d, and ms, ls are the number of leaked MSB and LSB, respectively.

   ### 2.2 Parametric Representation of d

   Combining the leaked MSB and LSB, d can be expressed as:

   d=d0+x⋅2ls

   - d0: The known part obtained by concatenating dMSB and dLSB;
   - x: The integer corresponding to the unknown intermediate bits, satisfying ∣x∣<X (where X is the boundary given in the problem).

   ## 3. Core Mathematical Transformation (Linking d to Factorization of N)

   ### 3.1 Polynomial Construction

   Define two linear polynomials in the polynomial ring Z[x,y]:

   f1(x)=x+a1,f2(y)=y+(N+1)

   where the constant a1 can be derived from the public e and the leaked dMSB,dLSB through a combination of modular inverse operations.

   ### 3.2 Linking y to Factorization of N

   Let y=−(p+q). Combining the property of Euler's totient function:

   φ(N)=(p−1)(q−1)=N−(p+q)+1

   Substitute y=−(p+q), we get:

   φ(N)=N+1+y

   **Core Conclusion** : If the small root of y can be solved, p+q=−y can be directly obtained, and then p,q can be solved by the quadratic equation:

   p,q=2(p+q)±(p+q)2−4N

   The factorization of the modulus N is thus completed.

   ## 4. Lattice Basis Reduction and Small Root Solution

   ### 4.1 Construction of Shifted Polynomial Family

   For the unknown variables x (bounded by ∣x∣<X) and y (bounded by ∣y∣<Y), construct the shifted polynomial family:

   f1(x)i1⋅f2(y)i2⋅(N−1)max(t−r1i1−r2i2,0)

   where i1,i2 are non-negative integers, and t,r1,r2 are parameters for lattice construction.

   ### 4.2 Lattice Reduction and Elimination for Root Solution

   1. Scale the coefficients of the above polynomials by (X,Y) and embed them into the basis vectors of an integer lattice;
   2. Perform LLL reduction on the lattice to obtain several low-degree polynomials corresponding to "short vectors";
   3. Solve the integer small roots (x0,y0) of the polynomials (i.e., the true values of x,y satisfying the boundaries) by the Gröbner basis elimination method.

   ## 5. Final Decryption Process

   1. **Factorize \**N\**** : Calculate p,q from y0=−(p+q);

   2. Compute the least common multiple of Euler's totient functions

      :

      

      ϕ=lcm(φ(p),φ(q))

   3. Derive the standard RSA private key exponent

      :

      

      drsa≡e−1(modϕ)

   4. Decrypt the plaintext

      :

      

      m≡cdrsa(modN)

   ### Summary

   1. The core construction of Cruel RSA is to generate p,q based on Blum primes and bind the private key d to the parameter L=2gab;
   2. The key to cracking is to transform the factorization problem of N into a polynomial small root solution problem, and recover p+q through LLL lattice reduction combined with Gröbner basis elimination;
   3. The decryption is finally completed by solving the standard RSA private key (finding the inverse modulo lcm(φ(p),φ(q))).