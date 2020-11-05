<?php

namespace App\Http\Controllers\Auth;

use App\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class ChangePasswordController extends Controller
{
    public function __construct(){
        $this->middleware('auth');
    }

    public function index() {
        return view('auth.passwords.change');
    }

    public function changepassword(Request $request) {
        $this->validate($request, [
            'oldpassword' => 'required',
            'password' => 'required|confirmed'
        ]);
        
        // Password from database
        $hashedPassword = Auth::user()->password;

        // Check if old password exists in table
        if (Hash::check($request->oldpassword, $hashedPassword)) {
            // Find logged in user
            $user = User::find(Auth::id());
            // Hash new password and overwrite old one
            $user->password = Hash::make($request->password);
            $user->save();
            Auth::logout();

            return redirect()->route('login')->with('successMsg', 'Password Changed Successfully!');
        } else {
            return redirect()->back()->with('errorMsg', 'Current Password Is Invalid!');
        }
    }
}
