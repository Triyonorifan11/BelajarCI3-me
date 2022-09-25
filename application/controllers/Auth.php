<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->load->library('form_validation');
    }

    public function index()
    {
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'required|trim|min_length[6]');

        if ($this->form_validation->run() == false) {
            $data['title'] = 'Login - MyApp CI';
            $this->load->view('templates/headerLogin_view', $data);
            $this->load->view('auth/login_view');
            $this->load->view('templates/footerLogin_view');
        } else {
            // valiadasi jika sukses
            $this->_login();
        }
    }

    private function _login()
    {
        $email = $this->input->post('email', true);
        $password = $this->input->post('password', true);

        $user = $this->db->get_where('tb_user', ['email' => $email])->row_array();
        if ($user) {
            // user ada
            if ($user['is_active'] == 1) {
                if (password_verify($password, $user['password'])) {

                    $data = [
                        'email' => $user['email'],
                        'rule_id' => $user['rule_id']
                    ];

                    $this->session->set_userdata($data);
                    redirect('user');
                } else {
                    $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Wrong password!</div>');
                    redirect('auth');
                }
            } else {
                $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">this Email has not activated!</div>');
                redirect('auth');
            }
        } else {
            $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Email is not registered!</div>');
            redirect('auth');
        }
    }


    public function registration()
    {
        $this->form_validation->set_rules('name', 'Name', 'required|trim');
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[tb_user.email]', [
            'is_unique' => 'This email has been registered'
        ]);
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[6]|matches[password2]', [
            'matches' => 'Password don`t match!!',
            'min_length' => 'Password too short!!'
        ]);
        $this->form_validation->set_rules('password2', 'Password', 'required|trim|matches[password1]');

        if ($this->form_validation->run() == false) {
            $data['title'] = 'Registration - MyApp CI';
            $this->load->view('templates/headerLogin_view', $data);
            $this->load->view('auth/register_view');
            $this->load->view('templates/footerLogin_view');
        } else {

            /* set default timezone */
            date_default_timezone_set("Asia/Jakarta");
            $data = [
                'name' => htmlspecialchars($this->input->post('name', true)),
                'email' => htmlspecialchars($this->input->post('email', true)),
                'image' => 'default.jpg',
                'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
                'rule_id' => 2,
                'is_active' => 1,
                'date_created' => date('Y-m-d H:i:s')
            ];

            $this->db->insert('tb_user', $data);
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Account has been created, Login!</div>');
            redirect('auth');
        }
    }

    public function logout()
    {
        $this->session->unset_userdata('email');
        $this->session->unset_userdata('rule_id');
        $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">You has been logout</div>');
        redirect('auth');
    }
}
