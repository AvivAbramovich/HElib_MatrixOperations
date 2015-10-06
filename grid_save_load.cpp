#include "Grid.h"

using namespace std;

int main(){
    //create a random matrix and save it in a file
    PTMatrix mat1(MatSize(6,4), 100);
    PTMatrixGrid grid(mat1, MatSize(2,2));
    ofstream outputFile("test_file.txt");
    
    //print the matrix
    mat1.print();
    //print the grid sub matrices
    for(unsigned int i=0; i < grid.size(); i++)
        for(unsigned int j=0; j < grid[i].size(); j++){
            cout << "grid["<<i<<","<<j<<"]:" << endl;
            grid[i][j].print();
        }
    
    //save to a file
    grid.save(outputFile);
    outputFile.close();
    
    //open a matrix from a file
    ifstream inFile("test_file.txt");
    PTMatrixGrid grid2(inFile);
    inFile.close();
    grid2.reunion().print();
    
    //change the matrix
    grid2[0][0](0,0) = 500;
    
    cout << "matrix after change: " << endl;
    grid2.reunion().print();
    
    //save it back to the file
    ofstream outFile("test_file.txt");
    grid2.save(outFile);
    outFile.close();
    return 0;
}