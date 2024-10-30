//
// Created by Şeyda Nur Güzelhan on 10/30/24.
//
#include "enn/mp-conv-utils.h"

vector<vector<vector<Ctxt>>> ENN::pack_images_mp(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding, int mp_factor) {

    int ci = x_s.size();
    int ci_cn = ceil(ci / cn);
    vector<vector<double>> x_inputs(ci_cn, vector<double>(cn*iw*ih));

    for (int i=0; i<ci_cn; i++){
        for (int j=0; j < mp_factor*ih; j++){
            for (int k=0; k < cn; k++) {
                for (int h=0; h < mp_factor; h++){
                    x_inputs[i][j*cn*mp_factor + k*mp_factor + h] = x_s[(j%mp_factor)*mp_factor + h][j/mp_factor*cn + k];
                }
            }
        }
    }
    for (int j=0; j<ci_cn; j++) {
        cout << x_inputs[j] << endl;
    }
    vector<Ctxt> ct_inputs;
    for (int i=0; i<ci_cn; i++){
        Ptxt temp = cc->MakeCKKSPackedPlaintext(x_inputs[i]);
        ct_inputs.push_back(cc->Encrypt(keys.publicKey, temp));
    }

    vector<vector<vector<Ctxt>>> c_rotations(ci_cn, vector<vector<Ctxt>>(min(cn,ci), vector<Ctxt>(f*f)));

    int mp_iw = iw * mp_factor;
    int mp_ih = ih * mp_factor;

    vector<int> rot_index = {-padding-mp_iw, -mp_iw, +padding-mp_iw, -padding, 0, +padding, -padding+mp_iw, mp_iw, +padding+mp_iw, mp_iw*mp_ih};
    cc->EvalRotateKeyGen(keys.secretKey, rot_index);


    if (f==3) {
        for (int i = 0; i < ci_cn; i++) {
            for (int j = 0; j < min(cn, ci); j++) {
                for (int k = 0; k < f * f; k++) {
                    c_rotations[i][j][k] = cc->EvalRotate(ct_inputs[i], rot_index[k]);
                }
                ct_inputs[i] = cc->EvalRotate(ct_inputs[i], mp_iw * mp_ih);
            }
        }
    }
    else if(f == 5){
        // complete
    }
    return c_rotations;
}

vector<vector<vector<double>>> ENN::pack_weights_mp(vector<vector<double>> weights, int cn, int f, int iw, int ih, int mp_factor) {

    int co = weights.size();
    int co_cn = ceil((double)co / cn);
    vector<vector<vector<double>>> weight_list(co_cn, vector<vector<double>>(f*f));
    vector<vector<vector<double>>> weight_list_mp(co_cn, vector<vector<double>>(f*f, vector<double>(iw*ih*mp_factor*mp_factor)));
    if (f==3 && iw*ih == 16) {
        for (int j = 0; j < co_cn; j++) {
            for (int i = 0; i < min(cn, co); i++) {
                weight_list[j][0].insert(
                    weight_list[j][0].end(),
                    {0, 0, 0, 0, 0, weights[i + j * cn][0], weights[i + j * cn][0], weights[i + j * cn][0], 0,
                     weights[i + j * cn][0], weights[i + j * cn][0], weights[i + j * cn][0], 0, weights[i + j * cn][0],
                     weights[i + j * cn][0], weights[i + j * cn][0]});
                weight_list[j][1].insert(
                    weight_list[j][1].end(),
                    {0, 0, 0, 0, weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1],
                     weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1],
                     weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1], weights[i + j * cn][1],
                     weights[i + j * cn][1]});
                weight_list[j][2].insert(
                    weight_list[j][2].end(),
                    {0, 0, 0, 0, weights[i + j * cn][2], weights[i + j * cn][2], weights[i + j * cn][2], 0,
                     weights[i + j * cn][2], weights[i + j * cn][2], weights[i + j * cn][2], 0, weights[i + j * cn][2],
                     weights[i + j * cn][2], weights[i + j * cn][2], 0});
                weight_list[j][3].insert(weight_list[j][3].end(),
                                         {0, weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3], 0,
                                          weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3], 0,
                                          weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3], 0,
                                          weights[i + j * cn][3], weights[i + j * cn][3], weights[i + j * cn][3]});
                weight_list[j][4].insert(
                    weight_list[j][4].end(),
                    {weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4],
                     weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4],
                     weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4],
                     weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4]});
                weight_list[j][5].insert(weight_list[j][5].end(),
                                         {weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0,
                                          weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0,
                                          weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0,
                                          weights[i + j * cn][5], weights[i + j * cn][5], weights[i + j * cn][5], 0});
                weight_list[j][6].insert(
                    weight_list[j][6].end(),
                    {0, weights[i + j * cn][6], weights[i + j * cn][6], weights[i + j * cn][6], 0,
                     weights[i + j * cn][6], weights[i + j * cn][6], weights[i + j * cn][6], 0, weights[i + j * cn][6],
                     weights[i + j * cn][6], weights[i + j * cn][6], 0, 0, 0, 0});
                weight_list[j][7].insert(
                    weight_list[j][7].end(),
                    {weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7],
                     weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7],
                     weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], weights[i + j * cn][7], 0,
                     0, 0, 0});
                weight_list[j][8].insert(
                    weight_list[j][8].end(),
                    {weights[i + j * cn][8], weights[i + j * cn][8], weights[i + j * cn][8], 0, weights[i + j * cn][8],
                     weights[i + j * cn][8], weights[i + j * cn][8], 0, weights[i + j * cn][8], weights[i + j * cn][8],
                     weights[i + j * cn][8], 0, 0, 0, 0, 0});
            }

            for (int m=0; m<weight_list[j].size(); m++){
                for (int n=0; n < iw*ih/mp_factor; n++){
                    for (int k=0; k<min(cn,co); k++) {
                        for (int h=0; h<mp_factor; h++){
                            weight_list_mp[j][m][n*min(cn,co)*mp_factor + k*mp_factor + h] = weight_list[j][m][16*((n%mp_factor)*mp_factor + h)+n/mp_factor*cn + k];
                        }
                    }
                }
            }
        }
    }
    else if (f==3 && iw*ih == 4) {       // Incorrect
        for (int j = 0; j < co_cn; j++) {
            for (int i = 0; i < min(cn, co); i++) {
                weight_list[j][0].insert(weight_list[j][0].end(),{0, 0, 0, weights[i + j * cn][0]});
                weight_list[j][1].insert(weight_list[j][1].end(),{0, 0, weights[i + j * cn][1], weights[i + j * cn][1]});
                weight_list[j][2].insert(weight_list[j][2].end(),{0, 0, weights[i + j * cn][2], 0});
                weight_list[j][3].insert(weight_list[j][3].end(),{0, weights[i + j * cn][3], 0, weights[i + j * cn][3]});
                weight_list[j][4].insert(weight_list[j][4].end(),{weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4], weights[i + j * cn][4]});
                weight_list[j][5].insert(weight_list[j][5].end(),{weights[i + j * cn][5], 0, weights[i + j * cn][5], 0});
                weight_list[j][6].insert(weight_list[j][6].end(),{0, weights[i + j * cn][6], 0, 0});
                weight_list[j][7].insert(weight_list[j][7].end(),{weights[i + j * cn][7], weights[i + j * cn][7], 0, 0});
                weight_list[j][8].insert(weight_list[j][8].end(),{weights[i + j * cn][8], 0, 0, 0});
            }
        }
    }
    else if (f == 5){
        // complete
    }

    return weight_list_mp;
}

vector<Ctxt> ENN::conv2d_mp(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, int f, int mp_iw, int padding, KeyPair<DCRTPoly> keys, int mp_factor, int cn, int ci, int co) {
    int co_cn = ceil((double)co/cn);
    int ci_cn = ceil((double)ci/cn);

    cout << "co_cn: " << co_cn << endl;
    cout << "ci_cn: " << ci_cn << endl;
    cout << "ci: " << ci << endl;
    auto cc   = c_rotations[0][0][0]->GetCryptoContext();

    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 3, -1, -2, -3});

    vector<Ctxt> mask;
    vector<vector<double>> mask_pt(mp_factor * mp_factor);
    mask_pt[0] = {1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    mask_pt[1] = {0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    mask_pt[2] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0};
    mask_pt[3] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1};
    for (int i = 0; i < mp_factor * mp_factor; i++) {
        mask.push_back(cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(mask_pt[i])));
    }

    vector<Ctxt> inter_out_ct;
    for (int j = 0; j < co_cn; j++) {
        vector<Ctxt> inter_in_ct;
        for (int h = 0; h < c_rotations[0].size(); h++) {
            for (int l = 0; l < c_rotations.size(); l++) {
                vector<Ctxt> conv_ct;
                for (int k = 0; k < f * f; k++) {
                    Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weight_list[j][k]);
                    Ctxt cMult     = cc->EvalMult(weight_pt, c_rotations[l][h][k]);
                    conv_ct.push_back(cMult);

                    //                        cout << endl << "wt: " << endl;
                    //                        cout << weight_list[j][k] << endl;
                    //                        Ptxt res1;
                    //                        cc->Decrypt(keys.secretKey, c_rotations[l][h][k], &res1);
                    //                        cout << "ct: " << endl;
                    //                        cout << res1 << endl;
                    //                        Ptxt res;
                    //                        cc->Decrypt(keys.secretKey, cMult, &res);
                    //                        cout << "cMult: " << endl;
                    //                        cout << res << endl;
                    //                        cout << "-------------------" << endl;
                }
                Ctxt inter_conv_sum     = cc->EvalAddMany(conv_ct);

                Ptxt res1;
                cc->Decrypt(keys.secretKey, inter_conv_sum, &res1);
                cout << endl << "ct: " << endl;
                cout << res1 << endl;

                inter_conv_sum += cc->EvalRotate(inter_conv_sum, 1);
                inter_conv_sum += cc->EvalRotate(inter_conv_sum, 2);
                inter_in_ct.push_back(inter_conv_sum);
            }
        }
        //        inter_out_sum      = cc->EvalMult(inter_out_sum, cc->MakeCKKSPackedPlaintext(mask_pt[j]));
        inter_out_ct.push_back(cc->EvalAddMany(inter_in_ct));
    }

    return inter_out_ct;
}
