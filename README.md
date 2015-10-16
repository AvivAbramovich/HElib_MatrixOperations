**Encrypted Matrix Operations using HElib**

I implemented encrypted matrices multiplication, and other matrices operations, in the **Homomorphic Encryption** scheme. I’m using the HElib by Shai Halevi, that implemented Fully Homomorphic Encryption scheme and vector operations like vectors element by element addition, subtraction and multiplication.

The multiplication algorithm described in my “_Diagonal Order Matrices Multiplication_”, that save the matrix as diagonal vectors, and the multiplication between the vectors, using SIMD operations, returns the result’s diagonal vector. That way of multiplication have some benefits:

It is the fastest way. Works about 10 times faster than the over multiplication algorithms that described in Shai’s “_Algorithm in HElib_” (The rows order and columns order)

In this algorithm, all the matrices in the same representation type, and no need to “match” the representation type to perform some kind of operations (for example: in Shai’s algorithm, you always need the second matrix in the multiplication to be columns order, and for matrices addition, you need them both to be in the same representation).

Shai’s article “_Algorithms in HElib_“, that describes how to multiply  matrix by vector, using only vectors operations, like these HElib implementing, and my 

My addition to HElib is classes that handle matrices, vectors and ‘Grid’ matrices, a “big” matrix that divided to grid of smaller matrices. These classes handle the plain text or encrypted data, and provide operations on the matrices or between the matrices, like get specific elements, encrypt a plain-text matrix, decrypt an encrypted matrix, or add/subtract/multiply two matrices/matrix-vector.

**Helping Classes**

1.1 MatSize

That class is help to provide data about the matrix size, and which operations is legal. This class is needed, because when we encrypt our data in HElib, the vectors size might to change. The **Ctxt** (an encrypted vector in HElib)  size (referred as **nslots**) set by various of parameters, and cannot be change to be fit to our data. We need to fit out data to nslots. So if we want to encrypt a vector that it’s size is smaller than nslots, we padding it with zeros to fit, but than we lost the information about the matrix dimensions size. The MatSize object is save the original matrix sizes, and say which operations is legit. for example, multiplication of 100*100 matrix with 20*100 matrix is not possible, so the multiplication would be aborted (or returned the original matrix in my implementation).

MatSize’s important methods:

MatSize operator*(const MatSize& other) const; //return the size of the multiplication result, or (0,0) if the multiplication is not possible because this.columns != other.rows

bool operator==(const MatSize& other) const;

bool canMultiply(const MatSize& other) const;

**2. Matrices Classes**

**2.1 PTMatrix**

This class represents a plain-text matrix, which each element in it is of type long. This class keep the matrix data, that save in **Diagonal Order**, as describes in Shai’s “_Algorithm in HElib_”, that means that each vector is a diagonal in the matrix, that starts in the first row of the matrix.

PTMatrix’s important methods:

EncryptedMatrix encrypt(const EncryptedArray&, const FHEPubKey&) const; //Encrypt the matrix

PTMatrix getSubMatrix(unsigned int, unsigned int, MatSize) const;

These methods allow us to encrypt the matrices, or handle the plain-text data.

**2.2 EncryptedMatrix**

This class represented an encrypted matrix. It holds the encrypted data (as vector of Ctxt’s), and it’s original size as MatSize object.

EncryptedMatrix’s important methods:

PTMatrix decrypt(const EncryptedArray&, const FHESecKey&) const; //decrypt the matrix

EncryptedMatrix operator*(const EncryptedMatrix&) const; //Matrix by matrix multiplication

Ctxt operator*(const Ctxt& vec) const; //matrix multyplication by vector

EncryptedMatrix operator+(const EncryptedMatrix& other) const; //Matrices addition

EncryptedMatrix operator-(const EncryptedMatrix& other) const; //Matrices subtraction

Note:

The first multiplication operator is matrices multiplication, as I described in “_Diagonal Order Matrices Multiplication_” that returns another EncryptedMatrix. sasasasd The second one is just like Shai’s described in his article, that returns a column vector. That not recommended, because you can’t create with them an EncryptedMatrix object later, and use them with my methods, because it is not diagonal order.

The &lt;. &gt;, &lt;=, &gt;= operators work ONLY when the plain text field is BINARY.

The operator == and != is base on HElib’s operator ==

**3. Matrix-Grid Classes**

The matrices operations work with classes at 2, but have few limitations/disadvantages, that related to the **nslots** value:

If we want to encrypt a vector that it’s size is less than nslots, we need to padding it with zeros. Not so horrible, but may cause some problems. For example, when using EncryptedMatrix in DiagonalOrder by Ctxt multiplication, the rotation operation wouldn’t work right, because the extra zeros, and the result might be incorrect.

It bound our matrix size. Say nslots is 100, so we can easily create a 2*100 matrix, 100*100 matrix,  1,000,000,000*100 matrix, but how would we create a 101*101 matrix? The answer is we can’t do it in the previous standard way, because 1 of the 2 matrix’s dimensions is bounded by nslots. 

For these reasons, we had to think about a solution that bypass these problems. The first thing we thought to do is try to control that nslots value, but it seems like a really hard work, and it also not so “controllable” because it depends on many parameters.

The second solution, that I implemented here and called it “**Matrix-Grid”**, is not such an original idea. It says “take the big matrix and break it to a smaller matrices”, creating some grid of matrices, or matrix of matrices. For example, I want to do multiply 2 1M on 1M matrices, but nslots is 100, so I can’t do it with a regular EncryptedMatrix, because it can’t hold any of these 2 matrices, So I break these matrices to a lot 100*100 matrices (but could be also 5*100 or 200*100 if I would like to), so I get a grid in size of 10,000*10,000, that each of it “cells” is an EncryptedMatrix, and the multiplication can be preformed as regular matrices multiplication, or any other algorithm. For example, in my implementation, there is a regular matrices multiplication, or Strassen’s Matrix multiplication algorithm (optional).

**3.1 PTMatrixGrid**

This class represents a plain-text matrix grid as described above. This class hold a vector of vectors of PTMatrix

PTMatrixGrid’s important methods:

PTMatrixGrid(const PTMatrix&, const MatSize); //A constructor that take a “big” PTMatrix, and break it to smaller matrices in the wanted size. using basically the PTMatrix::getSubMatrix method

PTMatrix reunion() const; //do the reverse way, take a grid and “reconstructing” it back to a big PTMatrix

EncryptedMatrixGrid encrypt(const EncryptedArray&, const FHEPubKey&) const; //encrypt the plain text grid

**3.2 PTVectorGrid**

Really similar to PTMatrix, but for vectors. Not really usefully, unless you want to preform a grid matrix multiplication by vector, and so you have to break that vector to a 1D grid as well.

PTVectorGrid’s important methods:

PTVectorGrid(const vector&lt;long&gt;&, unsigned int); //break the vector to a sub-vectors in the wanted size

EncryptedVectorGrid encrypt(const EncryptedArray&, const FHEPubKey&) const; //encrypt the vector

vector&lt;long&gt; reunion() const; //reconstruct the big vector

**3.3 EncryptedMatrixGrid**

This class represented an encrypted matrix grid

EncryptedMatrixGrid’s important methods:

PTMatrixGrid decrypt(const EncryptedArray&, const FHESecKey&) const; //decrypt the grid

EncryptedVectorGrid operator*(const EncryptedVectorGrid&) const; //a multiplication by vector-grid

EncryptedMatrixGrid operator*(const EncryptedMatrixGrid& other) const; //multiplication by another EncryptedMatrixGrid

EncryptedMatrixGrid operator+(const EncryptedMatrixGrid& other) const; //adding 2 matrix grids

EncryptedMatrixGrid operator-(const EncryptedMatrixGrid& other) const; //subtraction of 2 matrix grids

void enableStrassenMultiplication(unsigned int limit); //enable using Strassen’s matrices multiplication algorithm with O(n^log7) instead O(n^3). limit is the size the below that, it won’t use the Strassen’s algorithm, but a regular multiplication

void disableStrassenMultiplication(); //disable the Strassen’s algorithm

**3.3 EncryptedVectorGrid**

Same as EncryptedMatrixGrid but for vector. Usefully for encrypted matrix grid by vector grid multiplication

EncryptedVectorGrid’s important methods:

PTVectorGrid decrypt(const EncryptedArray&, const FHESecKey&) const; //decrypt the grid