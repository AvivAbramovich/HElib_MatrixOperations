//  Created by Aviv Abramovich on 4/08/15.
//  Copyright (c) 2015 Aviv Abramovich. All rights reserved.

#include "Matrices.h"

//This class purpose is to take a single matrix and break it down to grid of smaller matrices

class PTMatrixGrid;
class PTVectorGrid;
class EncryptedMatrixGrid;
class EncryptedVectorGrid;

//This class represents a plain text matrix that divided to smaller plain text matrices (PTMatrix)
class PTMatrixGrid{
friend class PTMatrix;
private:
    vector<vector<PTMatrix> > grid;
public:
    //C'tors
    PTMatrixGrid(const PTMatrix& matrix, const MatSize blockSize); //each PTMatrix save the MatrixRepresentation of the given PTMatrix
    PTMatrixGrid(const vector<vector<PTMatrix> >& matrixGrid);
    PTMatrixGrid(ifstream& file);   //read from a file
    
    //Encryption
    EncryptedMatrixGrid encrypt(const EncryptedArray& ea, const FHEPubKey& publicKey) const;
    EncryptedMatrixGrid encrypt(const FHEPubKey& publicKey) const;
    
    //PTMatrixGrid& resize(MatSize origSize, MatSize blockSize); //good after decryption when the blocks get in size of nslots. NOTE: change all the matrices representation into RowsOrder
    
    //Re-unite the grid to a one "big" matrix
    PTMatrix reunion() const;
    bool save(ofstream& file) const;
    
    unsigned int getRows() const;       //returns number of rows in the big matrix
    unsigned int getColumns() const;    //returns number of columns in the big matrix
    const vector<PTMatrix>& operator[](unsigned int i) const;  //returns the i-th vector of the grid. Not really useful, uses for inner operations
    vector<PTMatrix>& operator[](unsigned int i);
    unsigned int size() const;  //grid.size()

    MatSize getGridSize() const;    //returns the size of the grid as a Matsize object
    MatSize getMatrixSize() const;  //returns the total size of the matrix represented by that grid
    
    //operators
    //NOTE: same as I wrote in PTMatrix, the idea of Homomorphic Encryption is to do these operations on the encrypted data. These operations provided to test the correctness of the encrypted data operations and statistics of how slower them compared to the regular operations
    
    //Grids multiplication
    PTMatrixGrid operator*(const PTMatrixGrid& other) const;
    PTMatrixGrid operator*=(const PTMatrixGrid& other);
    
    //Grids Addition
    PTMatrixGrid operator+(const PTMatrixGrid& other) const;
    PTMatrixGrid operator+=(const PTMatrixGrid& other);
    
    //Grids Substraction
    PTMatrixGrid operator-(const PTMatrixGrid& other) const;
    PTMatrixGrid operator-=(const PTMatrixGrid& other);
    
    PTMatrixGrid operator>(const PTMatrixGrid& other) const;
    PTMatrixGrid operator<(const PTMatrixGrid& other) const;
    PTMatrixGrid operator>=(const PTMatrixGrid& other) const;
    PTMatrixGrid operator<=(const PTMatrixGrid& other) const;
    
    //Grids comparison
    bool operator==(const PTMatrixGrid& other) const;
    bool operator!=(const PTMatrixGrid& other) const;
    
    bool concat(const PTMatrixGrid& other);  //concat 2 matrices and returns true if concat is possible (and done). Uses for the Starssen's algorithm
    bool push(const PTMatrixGrid& other); //return true if pushing is possible (and done)
};

//This class represents a plain text vector divided to 1D grid
class PTVectorGrid{
private:
    vector<vector<long> > grid;
public:
    //C'tors
    PTVectorGrid(const vector<long>& vec, unsigned int size);
    PTVectorGrid(const vector<vector<long> >& gridVec);
    
    //Encryption
    EncryptedVectorGrid encrypt(const EncryptedArray& ea, const FHEPubKey& publicKey) const;
    EncryptedVectorGrid encrypt(const FHEPubKey& publicKey) const;
    
    vector<long> reunion() const;   //reunite to 1 "long" vector
    vector<long> operator[](unsigned int i) const;
    
    MatSize getVectorSize() const;
};

//This class represents an encrypted matrices grid. Useful to handle really big matrices, that HElib won't let you encrypt, and the operation may take very long time and be very noisy
class EncryptedMatrixGrid{
friend class EncryptedMatrix;
private:
    vector<vector<EncryptedMatrix> > grid;
    bool StrassenEnabled;                       //Is Strassen's matrices multiplication algorithm enabled bu the user for this grid
    unsigned int StrassenLimit;                 //What is the size that below that stop using Strassen's algorithm and using regular multiplication
public:
    EncryptedMatrixGrid(const vector<vector<EncryptedMatrix> >& matrix); //c'tor
    
    //Decryption
    PTMatrixGrid decrypt(const EncryptedArray& ea, const FHESecKey& secretKey) const;
    PTMatrixGrid decrypt(const FHESecKey& secretKey) const;
    
    //Operators:
    
    //Matrix by vector (bith as grids) multiplication
    EncryptedVectorGrid operator*(const EncryptedVectorGrid& vec) const;

    //Grids multiplication
    EncryptedMatrixGrid operator*(const EncryptedMatrixGrid& other) const;
    EncryptedMatrixGrid operator*=(const EncryptedMatrixGrid& other);
    
    //Grids Addition
    EncryptedMatrixGrid operator+(const EncryptedMatrixGrid& other) const;
    EncryptedMatrixGrid operator+=(const EncryptedMatrixGrid& other);

    //Grids Substraction
    EncryptedMatrixGrid operator-(const EncryptedMatrixGrid& other) const;
    EncryptedMatrixGrid operator-=(const EncryptedMatrixGrid& other);
    
    EncryptedMatrixGrid operator>(const EncryptedMatrixGrid& other) const;
    EncryptedMatrixGrid operator<(const EncryptedMatrixGrid& other) const;
    EncryptedMatrixGrid operator>=(const EncryptedMatrixGrid& other) const;
    EncryptedMatrixGrid operator<=(const EncryptedMatrixGrid& other) const;
    
    //Grids comparison. Again, it based on Ctxt:operator==
    bool operator==(const EncryptedMatrixGrid& other) const;
    bool operator!=(const EncryptedMatrixGrid& other) const;
    
    //get a sub grid. usefully for strassen algorithm
    EncryptedMatrixGrid getSubGrid(unsigned int firstRow, unsigned int firstColumn, unsigned int numRows, unsigned int numColumns) const;
    
    //enable/disable Strassen
    void enableStrassenMultiplication(unsigned int limit);
    void disableStrassenMultiplication();
    bool isStrassenEnabled() const;
    unsigned int getStrassenLimit() const;
    
    bool concat(const EncryptedMatrixGrid& other);  //return true if concating is possible (and done)
    bool push(const EncryptedMatrixGrid& other); //return true if pushing is possible (and done)

    MatSize getGridSize() const;
    unsigned int size() const;  //same as grid[0].size();
    vector<EncryptedMatrix> operator[](unsigned int i) const;
};

//This class represents a divided encrypted vector. Not so useful by itself, but can be helpful to multiply a big matrix by vector, by dividing them to grids
class EncryptedVectorGrid{
private:
    vector<Ctxt> grid;
public:
    EncryptedVectorGrid(vector<Ctxt>& vec); //C'tor
    
    //Decryption
    PTVectorGrid decrypt(const EncryptedArray& ea, const FHESecKey& secretKey) const;
    PTVectorGrid decrypt(const FHESecKey& secretKey) const;
    
    Ctxt operator[](unsigned int i) const;
    unsigned int size() const;
};