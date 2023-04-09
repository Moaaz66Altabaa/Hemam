<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register()
    {
        $validated = $this->validateRegistration();
        $user = User::create($validated);
        $user->password = Hash::make($validated['password']);
        $user->save();

        return response()->json([
            'status' => 1,
            'message' => 'User Registered Successfully!'
        ]);
    }


    public function login()
    {
        $credentials = request()->validate([
            'mobile' => ['required', 'string'],
            'password' => ['required', 'string'],

        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'status' => 0,
                'message' => 'Invalid Credentials'
            ]);
        }
        $user = Auth::user();
        $user->tokens()->delete();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 1,
            'message' => 'Logged In Successfully',
            'access_token' => $token
        ]);
    }

    public function validateRegistration()
    {
        return request()->validate([
            'first_name' => ['required', 'string'],
            'last_name' => ['required', 'string'],
            'mobile' => ['required', 'string', 'unique:users'],
            'password' => ['required', 'string', 'confirmed'],
        ]);
    }


}
