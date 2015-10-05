#include "Matrices.h"

ostringstream MatricesSizesNotMatch::cnvt;

/* ----- some helping functions ------ */
long myModulu(long num, long mod)
//the regular modulo operator on minus numbers make trouble when trying to calculate enteries in the diagonal matrices.
//for example, -7%3=-1, but I want it to be 2 (-7+3=-4, -4+3=-1, -1+3= 2)
{
    //adding "mod" to "num" until it positive
    while(num<0)
        num+=mod;
    return num%mod;
}

unsigned int numDigit(long num){ return (num/10)==0 ? 1:numDigit(num/10)+1; } //How much digits in the input number. Uses for a "nice" printing

unsigned int largestNumInMatrixDigits(vector<vector<long> > matrix) //Find the longest number in a matrix and returns it length (in digits). Uses for a "nice" printing
{
    int largest = 0;
    long temp;
    for(unsigned int i=0; i < matrix.size(); i++)
        for(unsigned int j=0; j<matrix[i].size(); j++)
            if((temp = numDigit(matrix[i][j])) > largest)
                largest = temp;
    return largest;
}
void printNum(long num, int size){
    int len = numDigit(num);
    cout << num;
    for(int i=len; i < size; i++)
        cout << " ";
}

Ctxt getNotVector(const EncryptedArray& ea, const FHEPubKey& publicKey){
    vector<long> not_vec(ea.size(), 1);    //vectors of 1, uses for NOT
    Ctxt not_ctxt(publicKey);
    ea.encrypt(not_ctxt, publicKey, not_vec);
    return not_ctxt;
}
/* --------------------- MatSize (matrices size operations) class --------------------*/
MatSize::MatSize(unsigned int first, unsigned int second): rows(first), columns(second) {}

MatSize MatSize::operator*(const MatSize& other) const{
    if(!canMultiply(other)){
        cout << "Sizes not accepted! first: ("<<rows<<"x"<<columns<<"), second: ("<<other.rows<<"x"<<other.columns<<"). return empty MatSize (0x0)" << endl;
        return MatSize();
    }
    return MatSize(rows, other.columns);
}

MatSize MatSize::transpose() { return ((*this) = MatSize(columns, rows)); }

MatSize MatSize::operator*=(const MatSize& other) { return ((*this) = (*this)*other); }

bool MatSize::operator==(const MatSize& other) const { return (rows == other.rows && columns == other.columns); }
bool MatSize::operator!=(const MatSize& other) const { return !(*this==other); }

bool MatSize::canMultiply(const MatSize& other) const { return columns == other.rows; }

bool MatSize::canAdd(const MatSize& other) const { return *(this) == other; }

void MatSize::print() const { cout << "Rows: " << rows << ", Columns: " << columns << endl; }

unsigned int MatSize::size() const { return rows*columns; }

bool MatSize::isSquare() const { return rows==columns; }

/* --------------------- PTMatrix (Plain Text Matrix) class --------------------------*/

PTMatrix::PTMatrix(vector<vector<long> > _matrix, bool diagonal){
    if(diagonal)
        matrix = _matrix;
    else{ //transform from regular (rows order) representation to diagonal
        matrix = vector<vector<long> >(_matrix[0].size(), vector<long>(_matrix.size(),0));
        for(unsigned int i=0, sz1 = matrix.size(); i < sz1; i++)
            for(unsigned int j=0, sz2 = matrix[i].size(); j < sz2; j++)
                matrix[i][j] = _matrix[j][(i+j)%sz1];
    }
}

PTMatrix::PTMatrix(MatSize sizes, unsigned int numbersLimit)
/*this constructor create a random matrix
params:
 sizes: - the size of the matrix
 numbersLimit = the values limit, that means that all the values in the matrix would be between 0 to numbersLimit (not included), default : 10
*/
{
    matrix = vector<vector<long> >(sizes.columns, vector<long>(sizes.rows));
    for(unsigned int i=0; i < matrix.size(); i++)
        for(unsigned int j=0; j< matrix[i].size(); j++)
            matrix[i][j] = rand() % numbersLimit;
}

PTMatrix::PTMatrix(ifstream& file)
/*read a matrix from a file
 the file format should be
 num_of_rows num_of_columns
 the matrix
 for example:
 2 3
 5 3 7
 1 4 6
 */
{
    string line, temp;
    int rows, cols;
    if (file.is_open())
    {
        getline(file, line); //get number of rows
        temp = line.substr(0, line.find(' '));
        rows = stoi(temp);
        temp = line.substr(line.find(' ')+1);
        cols = stoi(temp);
        
        matrix = vector<vector<long> >(cols, vector<long>(rows,0));
        for(int i=0; i < rows; i++)
        {
            getline(file,line);
            for(int j=0; j < cols; j++){
                temp = line.substr(0, line.find(' '));
                matrix[myModulu(j-i,matrix.size())][i] = stoi(temp);
                line = line.substr(line.find(' ')+1);
            }
        }
        file.close();
    }
    else
        cout << "Unable to open file";
}

bool PTMatrix::save(ofstream& file) const{
    if (file.is_open())
    {
        unsigned int rows = getRows(), cols = getColumns();
        file << rows << " " << cols << "\n";
        for(unsigned int i=0; i < rows; i++){
            for(unsigned int j=0; j < cols; j++)
                file << (*this)(i,j) << " ";
            file << "\n";
        }
        file.close();
    }
    else{
        cout << "Unable to open file";
        return false;
    }
    
    return true;
}

vector<vector<long> > PTMatrix::getMatrix() const{
    unsigned int rows = getRows(), cols = getColumns();
    vector<vector<long> > ret(rows, vector<long>(cols,0));
    for(unsigned int i=0; i < rows ; i++)
        for(unsigned int j=0; j < cols; j++)
            ret[i][j] = (*this)(i,j);
    return ret;
}

EncryptedMatrix PTMatrix::encrypt(const EncryptedArray& ea, const FHEPubKey& publicKey) const{
    vector<Ctxt> encMat(size(), Ctxt(publicKey));
    unsigned int nslots = ea.size();
    for(unsigned int i=0; i< size(); i++){
        vector<long> temp = matrix[i];
        temp.resize(nslots,0);
        ea.encrypt(encMat[i], publicKey, temp);
    }
    return EncryptedMatrix(encMat, MatSize(getRows(), getColumns()));
}

EncryptedMatrix PTMatrix::encrypt(const FHEPubKey& publicKey) const{
    EncryptedArray ea(publicKey.getContext());
    return encrypt(ea, publicKey);
}

long& PTMatrix::operator()(unsigned int row, unsigned int column){
    if(row >= getRows() || column >= getColumns())
    {
        cout << "Error, indices out of bound! MatSize: " << getRows() << "*" << getColumns() <<", indices: " << row << "*" << column << endl;
        throw out_of_range("Error, indices out of bound!");
    }
    int i = row, j = column; //casting to int so the subtraction be ok
    return matrix[myModulu(j-i,matrix.size())][row];
}

const long& PTMatrix::operator()(unsigned int row, unsigned int column) const{
    if(row >= getRows() || column >= getColumns())
    {
        cout << "Error, indices out of bound! MatSize: " << getRows() << "*" << getColumns() <<", indices: " << row << "*" << column << endl;
        throw out_of_range("Error, indices out of bound!");
    }
    int i = row, j = column; //casting to int so the subtraction be ok
    return matrix[myModulu(j-i,matrix.size())][row];
}

unsigned int PTMatrix::getRows() const { return matrix[0].size(); }

unsigned int PTMatrix::getColumns() const { return matrix.size(); }

void PTMatrix::print(string label) const{
    if(label.compare("")!=0)
        cout << label << endl;
    unsigned int primarySize = getRows();
    unsigned int secondarySize = getColumns();
    unsigned int cellSize = largestNumInMatrixDigits(matrix)+1; //+1 for space
    
    cout << " ";
    
    for(unsigned int i=0; i< secondarySize*cellSize; i++)
        cout << "-";
    cout << endl;
    for(unsigned int i=0; i< primarySize; i++)
    {
        cout << "|";
        for(unsigned int j=0; j< secondarySize; j++)
                printNum((*this)(i,j), cellSize);
        cout << "|" << endl;
    }
    cout << " ";
    for(unsigned int i=0; i< secondarySize*cellSize; i++)
        cout << "-";
    cout << endl;
}

PTMatrix PTMatrix::getSubMatrix(unsigned int i, unsigned int j, MatSize blockSize) const{
    unsigned int numRows = blockSize.rows, numCols = blockSize.columns;
    if(getRows() < i + numRows)
        numRows = getRows()-i;
    if(getColumns() < j + numCols)
        numCols = getColumns()-j;
    
    vector<vector<long> > result(numRows, vector<long>(numCols,0));
    for(unsigned int x=0; x < numRows; x++)
        for(unsigned int y=0; y < numCols; y++)
            result[x][y] = (*this)(i+x,j+y);
    return PTMatrix(result, false);
    
}

vector<long>& PTMatrix::operator[](unsigned int i) { return matrix[i]; }
const vector<long>& PTMatrix::operator[](unsigned int i) const { return matrix[i]; }

unsigned int PTMatrix::size() const { return matrix.size(); }

MatSize PTMatrix::getMatrixSize() const { return MatSize(getRows(), getColumns()); }

//operators

PTMatrix PTMatrix::operator*(const PTMatrix& other) const{
    //check sizes
    if(getColumns() != other.getRows())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    vector<vector<long> > res(getRows(), vector<long>(other.getColumns(),0));
    for(unsigned int i=0; i < res.size(); i++)
        for(unsigned int j=0; j < res[i].size(); j++)
            for(unsigned int k = 0; k < other.getRows(); k++)
                res[i][j] += (*this)(i,k)*other(k,j);
    
    return PTMatrix(res, false);
}

PTMatrix PTMatrix::operator*=(const PTMatrix& other){ return (*this) = (*this)*other; }

PTMatrix PTMatrix::operator+(const PTMatrix& other) const{
    //check sizes
    if(matrix.size() != other.matrix.size() || matrix[0].size() != other.matrix[0].size())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    unsigned int rows = getRows(), cols = getColumns();
    vector<vector<long> > res(rows, vector<long>(cols,0));
    for(unsigned int i=0; i < rows; i++)
        for(unsigned int j=0; j < cols; j++)
            res[i][j] = matrix[i][j]+other[i][j];
    return PTMatrix(res, false);
}

PTMatrix PTMatrix::operator+=(const PTMatrix& other){ return (*this) = (*this)+other; }

PTMatrix PTMatrix::operator-(const PTMatrix& other) const{
    //check sizes
    if(matrix.size() != other.matrix.size() || matrix[0].size() != other.matrix[0].size())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    unsigned int rows = getRows(), cols = getColumns();
    vector<vector<long> > res(rows, vector<long>(cols,0));
    for(unsigned int i=0; i < rows; i++)
        for(unsigned int j=0; j < cols; j++)
            res[i][j] = matrix[i][j]-other[i][j];
    return PTMatrix(res, false);

}

PTMatrix PTMatrix::operator-=(const PTMatrix& other){ return (*this) = (*this)-other; }

PTMatrix PTMatrix::operator>(const PTMatrix& other) const {
    //check sizes
    if(matrix.size() != other.size() || matrix[0].size() != other[0].size())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    unsigned sz1 = matrix[0].size(), sz2 = matrix.size();
    vector<vector<long> > res(sz1, vector<long>(sz2));
    for(unsigned int i=0; i < sz1; i++)
        for(unsigned int j=0; j < sz2; j++)
            res[i][j] = matrix[i][j] > other[i][j];
    return PTMatrix(res, true);
}

PTMatrix PTMatrix::operator<(const PTMatrix& other) const {
    //check sizes
    if(matrix.size() != other.size() || matrix[0].size() != other[0].size())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    unsigned sz1 = matrix[0].size(), sz2 = matrix.size();
    vector<vector<long> > res(sz1, vector<long>(sz2));
    for(unsigned int i=0; i < sz1; i++)
        for(unsigned int j=0; j < sz2; j++)
            res[i][j] = matrix[i][j] < other[i][j];
    return PTMatrix(res, true);
}

PTMatrix PTMatrix::operator>=(const PTMatrix& other) const {
    //check sizes
    if(matrix.size() != other.size() || matrix[0].size() != other[0].size())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    unsigned sz1 = matrix[0].size(), sz2 = matrix.size();
    vector<vector<long> > res(sz1, vector<long>(sz2));
    for(unsigned int i=0; i < sz1; i++)
        for(unsigned int j=0; j < sz2; j++)
            res[i][j] = matrix[i][j] >= other[i][j];
    return PTMatrix(res, true);
}

PTMatrix PTMatrix::operator<=(const PTMatrix& other) const {
    //check sizes
    if(matrix.size() != other.size() || matrix[0].size() != other[0].size())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    unsigned sz1 = matrix[0].size(), sz2 = matrix.size();
    vector<vector<long> > res(sz1, vector<long>(sz2));
    for(unsigned int i=0; i < sz1; i++)
        for(unsigned int j=0; j < sz2; j++)
            res[i][j] = matrix[i][j] <= other[i][j];
    return PTMatrix(res, true);
}

bool PTMatrix::operator==(const PTMatrix& other) const{
    if(matrix.size() != other.size() || matrix[0].size() != other[0].size())
        return false;
    for(unsigned int i=0, sz1 = getRows() ; i < sz1; i++)
        for(unsigned int j=0, sz2 = getColumns(); j < sz2; j++)
            if((*this)(i,j) != other(i,j))
                return false;
    return true;
}
bool PTMatrix::operator!=(const PTMatrix& other) const { return !(*this == other); }

PTMatrix PTMatrix::operator%(unsigned int p) const{
    vector<vector<long> > res = matrix;
    for(unsigned int i=0; i< size(); i++)
        for(unsigned int j=0; j < matrix[i].size(); j++)
            res[i][j] %= p;
    return PTMatrix(res, true);
}

PTMatrix PTMatrix::operator%=(unsigned int p) { return (*this) = (*this)%p; }

PTMatrix PTMatrix::mulWithMod(const PTMatrix& other, long p) const {
    //check sizes
    if(getColumns() != other.getRows())
        throw MatricesSizesNotMatch(getMatrixSize(), other.getMatrixSize());
    
    vector<vector<long> > res(getRows(), vector<long>(other.getColumns(),0));
    for(unsigned int i=0; i < res.size(); i++)
        for(unsigned int j=0; j < res[i].size(); j++)
            for(unsigned int k = 0; k < other.getRows(); k++){
                res[i][j] += (*this)(i,k)*other(k,j);
                res[i][j] %= p;
            }
    return PTMatrix(res, false);
}


/* --------------------- EncryptedMatrix class -------------*/
EncryptedMatrix::EncryptedMatrix(const vector<Ctxt>& encMatrix, const MatSize& origSize): matrix(encMatrix), matrixSize(origSize) {}

PTMatrix EncryptedMatrix::decrypt(const EncryptedArray& ea, const FHESecKey& secretKey) const {
    vector<vector<long> > ret(matrix.size());
    for(unsigned int i=0; i < matrix.size(); i++){
        ea.decrypt(matrix[i], secretKey, ret[i]);
        ret[i].resize(matrixSize.rows, 0);
    }
    return PTMatrix(ret, true);
}

PTMatrix EncryptedMatrix::decrypt(const FHESecKey& secretKey) const {
    EncryptedArray ea(secretKey.getContext());
    return decrypt(ea, secretKey);
}

//matrix multyplcation!
EncryptedMatrix EncryptedMatrix::operator*(const EncryptedMatrix& other) const
{
    //check sizes
    if(!matrixSize.canMultiply(other.matrixSize))
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
    
    Ctxt vec = matrix[0]; //save it for faster vec.getPubKey() in the loop
    EncryptedArray ea(vec.getContext());
    bool squares = getMatrixSize().isSquare() && other.getMatrixSize().isSquare() && getRows()==ea.size();  //Use the square matrices formula (much faster)
    //cout << "Square matrices formula? " << squares << endl;
    vector<Ctxt> res;
    int n = getRows(), m = getColumns(), k = other.getColumns(); //sizes: A(this):n*m, B(other):m*k
    for(int i=0; i < k; i++){
        Ctxt C(vec.getPubKey());
        for(int j=0; j< m; j++){
            //work by my formula: C_i = Sig j= 0 to n-1 [ A_i * (B_i-j%n <<< j) ]
            Ctxt B = other[myModulu(i-j,k)]; //B_i-j%n
            if(squares)
                ea.rotate(B, -j); //rotate j left, B_i-j%n <<< j (or -j right)
            else{
                //The general formula
                ea.shift(B, -j);  //shift j left
                int length = m-j;
                for(int itter=1;length < n; itter++){
                    Ctxt toChain = other[myModulu(i-j+(itter*m),k)];
                    ea.shift(toChain, length);  //shift length to right
                    B += toChain;
                    length+=m;
                }
            }
            B *= matrix[j];  //* A_j
            C += B;
        }
        res.push_back(C);
    }
    return EncryptedMatrix(res, matrixSize*other.matrixSize);
}

EncryptedMatrix EncryptedMatrix::operator*=(const EncryptedMatrix& other){ return ((*this) = (*this)*other); }

//matrices addition
EncryptedMatrix EncryptedMatrix::operator+(const EncryptedMatrix& other) const{
    if(!matrixSize.canAdd(other.getMatrixSize()))
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
        
    vector<Ctxt> ret = matrix;
    for(unsigned int i=0, len = matrix.size(); i < len; i++)
        ret[i] += other.matrix[i];
    return EncryptedMatrix(ret, matrixSize);
}

EncryptedMatrix EncryptedMatrix::operator+=(const EncryptedMatrix& other){ return ((*this) = (*this)+other); }

EncryptedMatrix EncryptedMatrix::operator-(const EncryptedMatrix& other) const{
    if(!matrixSize.canAdd(other.matrixSize))
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
        
    vector<Ctxt> ret = matrix;
    for(unsigned int i=0, len = matrix.size(); i < len; i++)
        ret[i] -= other.matrix[i];
    return EncryptedMatrix(ret, matrixSize);
}

//comparison operator (>, <, >= and <=)
/*NOTE: WORKING ONLY FOR BINARY FIELD (p=2)
 Concept: For any 2 binary encrypted vectors A and B, A[i] > B[i] for any i iff A[i] = 1 and B[i] =0
 The operators in binary fields are:
 operator* === AND
 operator+ === XOR
 + 1 === NOT
*/

EncryptedMatrix EncryptedMatrix::operator>(const EncryptedMatrix& other) const
//A[i] > B[i] ==> A[i] == 1 && B[i] == 0 ==> A[i] & !B[i] ===> A*(B+1)
{
    if(!matrixSize.canAdd(other.matrixSize)) //check sizes
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
    
    Ctxt vec = matrix[0]; //save it for faster vec.getPubKey() in the loop
    if(vec.getPtxtSpace()!= 2) //check that the computations is on binary field
        throw NotBinaryField();

    EncryptedArray ea(vec.getContext());
    Ctxt not_ctxt = getNotVector(ea, vec.getPubKey());
    vector<Ctxt> res = other.matrix;
    
    for(unsigned int i=0, sz = res.size(); i < sz; i++){
        res[i] += not_ctxt;
        res[i] *= matrix[i];
    }
    return EncryptedMatrix(res, matrixSize);
}

EncryptedMatrix EncryptedMatrix::operator<(const EncryptedMatrix& other) const
//A[i] < B[i] ==> A[i] == 0 && B[i] == 1 ==> !A[i] & B[i] ===> (A+1)*B
{
    if(!matrixSize.canAdd(other.matrixSize)) //check sizes
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
    
    Ctxt vec = matrix[0]; //save it for faster vec.getPubKey() in the loop
    if(vec.getPtxtSpace()!= 2) //check that the computations is on binary field
        throw NotBinaryField();

    EncryptedArray ea(vec.getContext());
    Ctxt not_ctxt = getNotVector(ea, vec.getPubKey());
    vector<Ctxt> res = matrix;
    
    for(unsigned int i=0, sz = res.size(); i < sz; i++){
        res[i] += not_ctxt;
        res[i] *= other[i];
    }
    return EncryptedMatrix(res, matrixSize);
}

EncryptedMatrix EncryptedMatrix::operator>=(const EncryptedMatrix& other) const
//A[i] >= B[i] ==> !(A[i] < B[i]) => !(!A[i] & B[i]) ===> ((A+1)*B)+1
{
    if(!matrixSize.canAdd(other.matrixSize)) //check sizes
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
    
    Ctxt vec = matrix[0]; //save it for faster vec.getPubKey() in the loop
    if(vec.getPtxtSpace()!= 2) //check that the computations is on binary field
        throw NotBinaryField();

    EncryptedArray ea(vec.getContext());
    Ctxt not_ctxt = getNotVector(ea, vec.getPubKey());
    vector<Ctxt> res = matrix;
    
    for(unsigned int i=0, sz = res.size(); i < sz; i++){
        res[i] += not_ctxt;
        res[i] *= other[i];
        res[i] += not_ctxt;
    }
    return EncryptedMatrix(res, matrixSize);
}


EncryptedMatrix EncryptedMatrix::operator<=(const EncryptedMatrix& other) const
//A[i] <= B[i] ==> !(A[i] > B[i]) => !(A[i] & !B[i]) ===> (A*(B+1))+1
{
    if(!matrixSize.canAdd(other.matrixSize)) //check sizes
        throw MatricesSizesNotMatch(matrixSize, other.matrixSize);
    
    Ctxt vec = matrix[0]; //save it for faster vec.getPubKey() in the loop
    if(vec.getPtxtSpace()!= 2) //check that the computations is on binary field
        throw NotBinaryField();
    
    EncryptedArray ea(vec.getContext());
    Ctxt not_ctxt = getNotVector(ea, vec.getPubKey());
    vector<Ctxt> res = other.matrix;
    
    for(unsigned int i=0, sz = res.size(); i < sz; i++){
        res[i] += not_ctxt;
        res[i] *= matrix[i];
        res[i] += not_ctxt;
    }
    return EncryptedMatrix(res, matrixSize);
}

EncryptedMatrix EncryptedMatrix::operator-=(const EncryptedMatrix& other){ return ((*this) = (*this)-other); }

bool EncryptedMatrix::operator==(const EncryptedMatrix& other) const{
    if(matrixSize != matrixSize)
        return false;
    for(unsigned int i=0, len= matrix.size(); i < len; i++)
        if(matrix[i] != other.matrix[i]) //base on Ctxt::operator==
            return false;
    return true;
}
bool EncryptedMatrix::operator!=(const EncryptedMatrix& other) const { return !(*this == other); }

//matrix multyplication by vector. NOTE: this return a column vector! so don't use it to create a matrix (unless you want it to be column vectors matrix)
Ctxt EncryptedMatrix::operator*(const Ctxt& vec) const{
    EncryptedArray ea(vec.getContext());
    Ctxt result(vec.getPubKey());
    int len = matrix.size();
    
    //TODO: Still not perfectlly working
    
    Ctxt fixedVec = vec;
    if(ea.size() != getRows()) //Fix the problem that if the size of the vector is not nslots, the zero padding make the rotation push zeros to the begining of the vector
    {
        //replicate the vector to fill instead of zero padding
        for(unsigned int length =getRows(); length < ea.size(); length*=2){
            Ctxt copyVec = fixedVec;
            ea.shift(copyVec, length);  //shift length to right
            fixedVec+=copyVec;
        }
    }
    
    for(int i=0; i < len; i++)
    {
        Ctxt rotatedVec(fixedVec);   //copy vec
        ea.rotate(rotatedVec, -i);   //rotate it i right (-i left)
        rotatedVec *= matrix[i];
        result += rotatedVec;
    }
    return result;
}

Ctxt& EncryptedMatrix::operator[](unsigned int i) { return matrix[i]; }
const Ctxt& EncryptedMatrix::operator[](unsigned int i) const { return matrix[i]; }

unsigned int EncryptedMatrix::getRows() const{ return getMatrixSize().rows; }

unsigned int EncryptedMatrix::getColumns() const { return getMatrixSize().columns; }

MatSize EncryptedMatrix::getMatrixSize() const { return matrixSize; }

EncryptedMatrix EncryptedMatrix::debugMul(const EncryptedMatrix& other) const{
    //check sizes
    if(!matrixSize.canMultiply(other.matrixSize)){
        cout << "ERROR! The matrices must be with suitable sizes!" << endl;
        return *this;  //return this
    }
    
    Ctxt vec = matrix[0]; //save it for faster vec.getPubKey() in the loop
    EncryptedArray ea(vec.getContext());
    bool squares = getMatrixSize().isSquare() && other.getMatrixSize().isSquare() && getRows()==ea.size();  //Use the square matrices formula (much faster)
    cout << "Square matrices? " << squares << endl;
    //cout << "Square matrices formula? " << squares << endl;
    vector<Ctxt> res;
    int n = getRows(), m = getColumns(), k = other.getColumns(); //sizes: A(this):n*m, B(other):m*k
    for(int i=0; i < k; i++){
        cout << "Multiplication: " << i+1 << " of " << k << endl;
        Ctxt C(vec.getPubKey());
        for(int j=0; j< m; j++){
            cout << "j: " << j+1 << " of " << m << endl;
            //work by my formula: C_i = Sig j= 0 to n-1 [ A_i * (B_i-j%n <<< j) ]
            Ctxt B = other[myModulu(i-j,k)]; //B_i-j%n
            cout << "rotate" << endl;
            if(squares)
                ea.rotate(B, n-j); //rotate j left, B_i-j%n <<< j (or -j right)
            else{
                //The general formula
                ea.shift(B, -j);  //shift j left
                int length = m-j;
                for(int itter=1;length < n; itter++){
                    Ctxt toChain = other[myModulu(i-j+(itter*m),k)];
                    ea.shift(toChain, length);  //shift length to right
                    B += toChain;
                    length+=m;
                }
            }
            cout << "mul" << endl;
            B *= matrix[j];  //* A_j
            cout << "add" << endl;
            C += B;
        }
        res.push_back(C);
    }
    return EncryptedMatrix(res, matrixSize*other.matrixSize);
}
