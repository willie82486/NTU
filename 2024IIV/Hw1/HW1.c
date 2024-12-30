#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>

using namespace std;

struct Msg{
    int    priority;
    double transmissionTime;
    double period; 
};

double computeResponseTime(int id, vector<Msg>& vecMsg, double tau);

int main(void)
{
    ifstream file("input.dat");
    if (!file) {
        cerr << "Unable to open file\n";
        return 1;
    }

    vector<Msg> vecMsg;
    int num;
    double tau;

    file >> num;
    file >> tau;

    string line;
    Msg msg;
    while(file>> msg.priority >> msg.transmissionTime >> msg.period){
        vecMsg.push_back(msg);
        if (vecMsg.size() >= num) break;
    }
    file.close();
    
    // compute response time    
    int id = 0;
    vector<double> vecResponseTime;
    while(id < num){
        double responseTime = computeResponseTime(id, vecMsg, tau);
        vecResponseTime.push_back(responseTime);
        id += 1;
    }
    
    int count = 0;
    for(auto& time : vecResponseTime){
        cout << "Index of Msg is "<< count << " and its response time is " << time << endl;
        count += 1;
    }
    return 0;
}

double computeResponseTime(int id, vector<Msg>& vecMsg, double tau)
{
    double responseTime = 0;
    double Q = 0, B = 0;
    
    // set block time
    for(auto& msg : vecMsg){
        if(msg.priority >= vecMsg[id].priority && msg.transmissionTime > B){
            B = msg.transmissionTime;
        }
    }
    Q = B;
    
    while(1){
        double rhs = 0.0;
        rhs += B;
        for(auto& msg : vecMsg){
            if(msg.priority < vecMsg[id].priority){
                rhs += ceil( (Q+tau)/msg.period ) * msg.transmissionTime;
            }
        }

        if(rhs + vecMsg[id].transmissionTime > vecMsg[id].period){
            cerr << "The system is not scheduable!" <<endl;
            return 1;
        }
        else if(Q == rhs){
            responseTime = Q + vecMsg[id].transmissionTime;
            return responseTime;
        }

        else{
            Q = rhs;
        }
    }
    return 1;
}
