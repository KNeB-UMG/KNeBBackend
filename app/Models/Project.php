<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Project extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'description',
        'participants',
        'start_date',
        'end_date',
        'technologies',
        'project_link',
        'repo_link',
        'file_id'
    ];

    protected $casts = [
        'participants' => 'array',
        'technologies' => 'array',
        'start_date' => 'date',
        'end_date' => 'date'
    ];

    public function file(): BelongsTo
    {
        return $this->belongsTo(File::class);
    }

    public function technologies(): BelongsToMany
    {
        return $this->belongsToMany(Technology::class, 'project_technology')
            ->withTimestamps();
    }
}
