<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('files', function (Blueprint $table) {
            $table->id();
            $table->foreignId('uploaded_by')->constrained('members');
            $table->string('file_type');
            $table->string('category');
            $table->string('permissions');
            $table->integer('size');
            $table->string('original_name');
            $table->string('file_path');
            $table->string('mime_type');
            $table->timestamps();
        });
    }

    public function down()
    {
    }
};
