#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>
#include <stdlib.h>
#include <algorithm>
using namespace std;

#define TEMPERATURE         1000.0
#define COOL_RATE           0.9
#define ANNEALING_INTERVAL  20

struct Msg{
    int     id; 
    int     priority;
    double  transmissionTime;
    double  period; 
};

double costFun_ResponseTime(int numOfMsg, vector<Msg>& vecMsg, double tau);
bool cmpPriorty(Msg A, Msg B);

int main(int argc, char *argv[])
{
    srand(time(NULL));
    string fileName = argv[1];
    ifstream file(fileName);

    vector<Msg> vecMsg;  
    int     numOfMsg; 
    double  tau;
    string  line;
    file >> numOfMsg >> tau;

    int id_Msg = 0;
    while(id_Msg < numOfMsg){
        Msg msg;
        msg.id = id_Msg;
        file >> msg.priority >> msg.transmissionTime >> msg.period;
        vecMsg.push_back(msg);
        id_Msg++;
    }
    file.close();
    
    int trial_count = 10;
    while(trial_count--){
        double temperature  = TEMPERATURE;
        double coolRate     = COOL_RATE;
        int annealingInterv = ANNEALING_INTERVAL;
        int round           = 0;
        vector<Msg> S;
        vector<Msg> S_star;
        S      = vecMsg;
        S_star = S;
        while( temperature >  1e-8 ){
            vector<Msg> S_prime = S;
            int random_idx1 = rand() % numOfMsg;
            int random_idx2;
            do{
                random_idx2 = rand() % numOfMsg;
            }while(random_idx1 == random_idx2);
            
            // swap priority
            int tmpPriority;
            tmpPriority = S[random_idx1].priority;
            S_prime[random_idx1].priority = S_prime[random_idx2].priority;
            S_prime[random_idx2].priority = tmpPriority; 
            
            // cost    
            double costS       = costFun_ResponseTime(numOfMsg, S,       tau);
            double costS_prime = costFun_ResponseTime(numOfMsg, S_prime, tau);
            double costS_star  = costFun_ResponseTime(numOfMsg, S_star,  tau);
            // update new best solution 
            if(costS_prime < costS_star){
                S_star = S_prime;
            } 
             
            double delta_cost = costS_prime - costS;
            if(delta_cost <= 0){
                S = S_prime;
            }
            else{
                double random_number = double(rand() % 100) / 100;
                double prob          = exp(-delta_cost /temperature);
                if( random_number < prob){
                    S = S_prime;
                }
            }
            // update info    
            round += 1;
            if( round % annealingInterv == 0){
                temperature *= coolRate;
            }
        }
        cout << "Msg order in best objective value" << endl;    
        sort(S_star.begin(), S_star.end(), cmpPriorty);
        for(auto& msg : S_star){
            cout << msg.id << endl;
        }
        cout << "Best objective value : "<< costFun_ResponseTime(numOfMsg, S_star, tau) << endl;
    }
}
double costFun_ResponseTime(int numOfMsg, vector<Msg>& vecMsg, double tau)
{
    double responseTime[numOfMsg] = {0};
    double Q[numOfMsg]            = {0};
    double B[numOfMsg]            = {0};
    double notScheduable_pay      = 1000;
    double cost                   = 0;

    // Compute block time of each Msg
    for(int id = 0; id < numOfMsg; id++){
        for(auto& msg : vecMsg){
            if(msg.priority >= vecMsg[id].priority && msg.transmissionTime > B[id]){
                B[id] = msg.transmissionTime;
            }
        }
        Q[id]= B[id];
    }
    
    for(int id = 0; id < numOfMsg; id++){
        while(1){
            double rhs = 0.0;
            rhs += B[id];
            // Compute RHS
            for(auto& msg : vecMsg){
                if(msg.priority < vecMsg[id].priority){
                    rhs += ceil( (Q[id]+tau)/msg.period ) * msg.transmissionTime;
                }
            }
            // Check RHS
            if(rhs + vecMsg[id].transmissionTime > vecMsg[id].period){
                responseTime[id] = notScheduable_pay;
                break;
            }
            else if(Q[id] == rhs){
                responseTime[id] = Q[id] + vecMsg[id].transmissionTime;
                break;
            }
            else{
                Q[id] = rhs;
            }
        }
    cost += responseTime[id];
    }
    
    return cost;
}

bool cmpPriorty(Msg A, Msg B)
{
    return A.priority < B.priority;
} 
